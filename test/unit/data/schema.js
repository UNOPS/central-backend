const appRoot = require('app-root-path');
const should = require('should');
const { getFormFields, sanitizeFieldsForOdata, SchemaStack, expectedFormAttachments, injectPublicKey, addVersionSuffix, setVersion } = require(appRoot + '/lib/data/schema');
const { fieldsFor, MockField } = require(appRoot + '/test/util/schema');
const { toTraversable } = require(appRoot + '/lib/util/xml');
const testData = require(appRoot + '/test/data/xml');

describe('form schema', () => {
  describe('parsing', () => {
    it('should retrieve a set of fields with their names and types', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <age/>
                  <hometown/>
                </data>
              </instance>
              <bind nodeset="/data/name" type="string"/>
              <bind type="int" nodeset="/data/age"/>
              <bind nodeset="/data/hometown" type="select1"/>
            </model>
          </h:head>
        </h:html>`;
      return getFormFields(xml).then((schema) => {
        schema.should.eql([
          { name: 'name', path: '/name', type: 'string', order: 0 },
          { name: 'age', path: '/age', type: 'int', order: 1 },
          { name: 'hometown', path: '/hometown', type: 'select1', order: 2 }
        ]);
      });
    });

    it('should work with relative paths', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <age/>
                  <hometown/>
                </data>
              </instance>
              <bind nodeset="name" type="string"/>
              <bind type="int" nodeset="age"/>
              <bind nodeset="hometown" type="select1"/>
            </model>
          </h:head>
        </h:html>`;
      return getFormFields(xml).then((schema) => {
        schema.should.eql([
          { name: 'name', path: '/name', type: 'string', order: 0 },
          { name: 'age', path: '/age', type: 'int', order: 1 },
          { name: 'hometown', path: '/hometown', type: 'select1', order: 2 }
        ]);
      });
    });

    it('should handle (and then strip) namespaced bindings correctly', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <orx:meta>
                    <orx:instanceID/>
                  </orx:meta>
                  <name/>
                  <age/>
                </data>
              </instance>
              <bind nodeset="/data/orx:meta/orx:instanceID" type="string"/>
              <bind nodeset="/data/name" type="string"/>
              <bind type="int" nodeset="/data/age"/>
            </model>
          </h:head>
        </h:html>`;
      return getFormFields(xml).then((schema) => {
        schema.should.eql([
          { name: 'meta', path: '/meta', type: 'structure', order: 0 },
          { name: 'instanceID', path: '/meta/instanceID', type: 'string', order: 1 },
          { name: 'name', path: '/name', type: 'string', order: 2 },
          { name: 'age', path: '/age', type: 'int', order: 3 }
        ]);
      });
    });

    it('should deal correctly with nonbinding nested nodes', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <occupation>
                    <title/>
                    <salary/>
                    <dates>
                      <joined/>
                      <departed/>
                    </dates>
                  </occupation>
                </data>
              </instance>
              <bind nodeset="/data/name" type="string"/>
              <bind nodeset="/data/occupation/title" type="string"/>
              <bind nodeset="/data/occupation/salary" type="decimal"/>
              <bind nodeset="/data/occupation/dates/joined" type="date"/>
              <bind nodeset="/data/occupation/dates/departed" type="date"/>
            </model>
          </h:head>
        </h:html>`;
      return getFormFields(xml).then((schema) => {
        schema.should.eql([
          { name: 'name', path: '/name', type: 'string', order: 0 },
          { name: 'occupation', path: '/occupation', type: 'structure', order: 1 },
          { name: 'title', path: '/occupation/title', type: 'string', order: 2 },
          { name: 'salary', path: '/occupation/salary', type: 'decimal', order: 3 },
          { name: 'dates', path: '/occupation/dates', type: 'structure', order: 4 },
          { name: 'joined', path: '/occupation/dates/joined', type: 'date', order: 5 },
          { name: 'departed', path: '/occupation/dates/departed', type: 'date', order: 6 }
        ]);
      });
    });

    it('should deal correctly with structure nodes with bindings', () => { // gh147
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <occupation>
                    <title/>
                    <dates>
                      <joined/>
                      <departed/>
                    </dates>
                    <salary/>
                  </occupation>
                </data>
              </instance>
              <bind nodeset="/data/name" type="string"/>
              <bind nodeset="/data/occupation" relevant="/data/name='liz'"/>
              <bind nodeset="/data/occupation/title" type="string"/>
              <bind nodeset="/data/occupation/dates" relevant="true()"/>
              <bind nodeset="/data/occupation/dates/joined" type="date"/>
              <bind nodeset="/data/occupation/dates/departed" type="date"/>
              <bind nodeset="/data/occupation/salary" type="decimal"/>
            </model>
          </h:head>
        </h:html>`;
      return getFormFields(xml).then((schema) => {
        schema.should.eql([
          { name: 'name', path: '/name', type: 'string', order: 0 },
          { name: 'occupation', path: '/occupation', type: 'structure', order: 1 },
          { name: 'title', path: '/occupation/title', type: 'string', order: 2 },
          { name: 'dates', path: '/occupation/dates', type: 'structure', order: 3 },
          { name: 'joined', path: '/occupation/dates/joined', type: 'date', order: 4 },
          { name: 'departed', path: '/occupation/dates/departed', type: 'date', order: 5 },
          { name: 'salary', path: '/occupation/salary', type: 'decimal', order: 6 }
        ]);
      });
    });

    it('should deal correctly with repeats', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <children>
                    <child>
                      <name/>
                      <toy>
                        <name/>
                      </toy>
                    </child>
                  </children>
                </data>
              </instance>
              <bind nodeset="/data/name" type="string"/>
              <bind nodeset="/data/children/child/name" type="string"/>
              <bind nodeset="/data/children/child/toy/name" type="string"/>
            </model>
          </h:head>
          <h:body>
            <input ref="/data/name">
              <label>What is your name?</label>
            </input>
            <group ref="/data/children/child">
              <label>Child</label>
              <repeat nodeset="/data/children/child">
                <input ref="/data/children/child/name">
                  <label>What is the child's name?</label>
                </input>
                <group ref="/data/children/child/toy">
                  <label>Child</label>
                  <repeat nodeset="/data/children/child/toy">
                    <input ref="/data/children/child/toy/name">
                      <label>What is the toy's name?</label>
                    </input>
                  </repeat>
                </group>
              </repeat>
            </group>
          </h:body>
        </h:html>`;
      return getFormFields(xml).then((schema) => {
        schema.should.eql([
          { name: 'name', path: '/name', type: 'string', order: 0 },
          { name: 'children', path: '/children', type: 'structure', order: 1 },
          { name: 'child', path: '/children/child', type: 'repeat', order: 2 },
          { name: 'name', path: '/children/child/name', type: 'string', order: 3 },
          { name: 'toy', path: '/children/child/toy', type: 'repeat', order: 4 },
          { name: 'name', path: '/children/child/toy/name', type: 'string', order: 5 }
        ]);
      });
    });

    it('should ignore further repeat instances', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <children>
                    <child>
                      <name/>
                      <toy>
                        <name/>
                      </toy>
                    </child>
                    <child>
                      <name/>
                      <toy>
                        <name/>
                      </toy>
                    </child>
                  </children>
                </data>
              </instance>
              <bind nodeset="/data/name" type="string"/>
              <bind nodeset="/data/children/child/name" type="string"/>
              <bind nodeset="/data/children/child/toy/name" type="string"/>
            </model>
          </h:head>
          <h:body>
            <input ref="/data/name">
              <label>What is your name?</label>
            </input>
            <group ref="/data/children/child">
              <label>Child</label>
              <repeat nodeset="/data/children/child">
                <input ref="/data/children/child/name">
                  <label>What is the child's name?</label>
                </input>
                <group ref="/data/children/child/toy">
                  <label>Child</label>
                  <repeat nodeset="/data/children/child/toy">
                    <input ref="/data/children/child/toy/name">
                      <label>What is the toy's name?</label>
                    </input>
                  </repeat>
                </group>
              </repeat>
            </group>
          </h:body>
        </h:html>`;
      return getFormFields(xml).then((schema) => {
        schema.should.eql([
          { name: 'name', path: '/name', type: 'string', order: 0 },
          { name: 'children', path: '/children', type: 'structure', order: 1 },
          { name: 'child', path: '/children/child', type: 'repeat', order: 2 },
          { name: 'name', path: '/children/child/name', type: 'string', order: 3 },
          { name: 'toy', path: '/children/child/toy', type: 'repeat', order: 4 },
          { name: 'name', path: '/children/child/toy/name', type: 'string', order: 5 }
        ]);
      });
    });

    it('should count correctly after ignoring repeated repeat instances', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <children>
                    <child>
                      <name/>
                      <toy>
                        <name/>
                      </toy>
                    </child>
                    <child>
                      <name/>
                      <toy>
                        <name/>
                      </toy>
                    </child>
                  </children>
                  <age/>
                </data>
              </instance>
              <bind nodeset="/data/name" type="string"/>
              <bind nodeset="/data/children/child/name" type="string"/>
              <bind nodeset="/data/children/child/toy/name" type="string"/>
              <bind nodeset="/data/age" type="int"/>
            </model>
          </h:head>
          <h:body>
            <input ref="/data/name">
              <label>What is your name?</label>
            </input>
            <group ref="/data/children/child">
              <label>Child</label>
              <repeat nodeset="/data/children/child">
                <input ref="/data/children/child/name">
                  <label>What is the child's name?</label>
                </input>
                <group ref="/data/children/child/toy">
                  <label>Child</label>
                  <repeat nodeset="/data/children/child/toy">
                    <input ref="/data/children/child/toy/name">
                      <label>What is the toy's name?</label>
                    </input>
                  </repeat>
                </group>
              </repeat>
            </group>
            <input ref="/data/age">
              <label>What is your age?</label>
            </input>
          </h:body>
        </h:html>`;
      return getFormFields(xml).then((schema) => {
        schema.should.eql([
          { name: 'name', path: '/name', type: 'string', order: 0 },
          { name: 'children', path: '/children', type: 'structure', order: 1 },
          { name: 'child', path: '/children/child', type: 'repeat', order: 2 },
          { name: 'name', path: '/children/child/name', type: 'string', order: 3 },
          { name: 'toy', path: '/children/child/toy', type: 'repeat', order: 4 },
          { name: 'name', path: '/children/child/toy/name', type: 'string', order: 5 },
          { name: 'age', path: '/age', type: 'int', order: 6 }
        ]);
      });
    });

    it('should fail on nonlocal extraneous repeat instances', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <children>
                    <child>
                      <name/>
                      <toy>
                        <name/>
                      </toy>
                    </child>
                  </children>
                  <children>
                    <child>
                      <name/>
                      <toy>
                        <name/>
                      </toy>
                    </child>
                  </children>
                </data>
              </instance>
              <bind nodeset="/data/name" type="string"/>
              <bind nodeset="/data/children/child/name" type="string"/>
              <bind nodeset="/data/children/child/toy/name" type="string"/>
            </model>
          </h:head>
          <h:body>
            <input ref="/data/name">
              <label>What is your name?</label>
            </input>
            <group ref="/data/children/child">
              <label>Child</label>
              <repeat nodeset="/data/children/child">
                <input ref="/data/children/child/name">
                  <label>What is the child's name?</label>
                </input>
                <group ref="/data/children/child/toy">
                  <label>Child</label>
                  <repeat nodeset="/data/children/child/toy">
                    <input ref="/data/children/child/toy/name">
                      <label>What is the toy's name?</label>
                    </input>
                  </repeat>
                </group>
              </repeat>
            </group>
          </h:body>
        </h:html>`;
      return getFormFields(xml).then((schema) => {
        schema.should.eql([
          { name: 'name', path: '/name', type: 'string', order: 0 },
          { name: 'children', path: '/children', type: 'structure', order: 1 },
          { name: 'child', path: '/children/child', type: 'repeat', order: 2 },
          { name: 'name', path: '/children/child/name', type: 'string', order: 3 },
          { name: 'toy', path: '/children/child/toy', type: 'repeat', order: 4 },
          { name: 'name', path: '/children/child/toy/name', type: 'string', order: 5 },
          { name: 'children', path: '/children', type: 'structure', order: 6 },
          { name: 'child', path: '/children/child', type: 'repeat', order: 7 },
          { name: 'name', path: '/children/child/name', type: 'string', order: 8 },
          { name: 'toy', path: '/children/child/toy', type: 'repeat', order: 9 },
          { name: 'name', path: '/children/child/toy/name', type: 'string', order: 10 }
        ]);
      });
    });

    it('should mark binary fields as such', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <orx:meta>
                    <orx:audit/>
                  </orx:meta>
                  <name/>
                  <photo/>
                </data>
              </instance>
              <bind nodeset="/meta/audit"/>
              <bind nodeset="/data/name" type="string"/>
              <bind nodeset="/data/photo" type="binary"/>
            </model>
          </h:head>
        </h:html>`;
      return getFormFields(xml).then((schema) => {
        schema.should.eql([
          { name: 'meta', path: '/meta', type: 'structure', order: 0 },
          { name: 'audit', path: '/meta/audit', type: 'unknown', binary: true, order: 1 },
          { name: 'name', path: '/name', type: 'string', order: 2 },
          { name: 'photo', path: '/photo', type: 'binary', binary: true, order: 3 }
        ]);
      });
    });
  });

  describe('SchemaStack', () => {
    describe('navigation', () => {
      it('should drop the envelope wrapper before proceeding', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data').should.equal(SchemaStack.Wrapper);
          should.not.exist(stack.head());
        }));

      it('should navigate into root fields', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data').should.equal(SchemaStack.Wrapper);
          stack.push('name').should.eql(new MockField({ name: 'name', path: '/name', type: 'string', order: 2 }));
        }));

      it('should navigate out of root fields', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.push('name');
          stack.pop().should.eql(new MockField({ name: 'name', path: '/name', type: 'string', order: 2 }));
          should.not.exist(stack.head());
        }));

      it('should navigate into structures', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.push('meta').should.eql(new MockField({ name: 'meta', path: '/meta', type: 'structure', order: 0 }));
          stack.push('instanceID').should.eql(new MockField({ name: 'instanceID', path: '/meta/instanceID', type: 'string', order: 1 }));
        }));

      it('should ignore namespaces', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.push('orx:meta').should.eql(new MockField({ name: 'meta', path: '/meta', type: 'structure', order: 0 }));
          stack.push('orx:instanceID').should.eql(new MockField({ name: 'instanceID', path: '/meta/instanceID', type: 'string', order: 1 }));
        }));

      it('should navigate out of structures', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.push('meta');
          stack.push('instanceID');
          stack.pop().should.eql(new MockField({ name: 'instanceID', path: '/meta/instanceID', type: 'string', order: 1 }));
          stack.pop().should.eql(new MockField({ name: 'meta', path: '/meta', type: 'structure', order: 0 }));
        }));

      it('should navigate in/out of unknown fields', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          should.not.exist(stack.push('something'));
          should.not.exist(stack.pop());
          should.not.exist(stack.head());
          stack.push('name').should.eql(new MockField({ name: 'name', path: '/name', type: 'string', order: 2 }));
        }));

      it('should not indicate exit upon return to root', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.push('children');
          stack.push('child');
          stack.pop();
          stack.pop();
          stack.hasExited().should.equal(false);
        }));

      it('should indicate exit upon pop past root', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.push('children');
          stack.push('child');
          stack.pop();
          stack.pop();
          stack.pop();
          stack.hasExited().should.equal(true);
        }));
    });

    describe('children', () => {
      it('should give root children', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.children().should.eql([
            new MockField({ name: 'meta', path: '/meta', type: 'structure', order: 0 }),
            new MockField({ name: 'name', path: '/name', type: 'string', order: 2 }),
            new MockField({ name: 'children', path: '/children', type: 'structure', order: 3 })
          ]);
        }));

      it('should give structure children', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.push('meta');
          stack.children().should.eql([
            new MockField({ name: 'instanceID', path: '/meta/instanceID', type: 'string', order: 1 })
          ]);
        }));

      it('should give repeat children', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.push('children');
          stack.push('child');
          stack.children().should.eql([
            new MockField({ name: 'name', path: '/children/child/name', type: 'string', order: 5 }),
            new MockField({ name: 'toys', path: '/children/child/toys', type: 'structure', order: 6 })
          ]);
        }));

      it('should not be fooled by path prefix extensions', () => fieldsFor(`<?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <children jr:template="">
                    <name/>
                  </children>
                  <children-status/>
                </data>
              </instance>
              <bind nodeset="/data/name" type="string"/>
              <bind nodeset="/data/children/name" type="string"/>
              <bind nodeset="/data/children-status" type="select1"/>
            </model>
          </h:head>
          <h:body>
            <repeat nodeset="/data/children">
              <input ref="/data/children/name">
                <label>What is the child's name?</label>
              </input>
            </repeat>
          </h:body>
        </h:html>`)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.push('children');
          stack.children().should.eql([
            new MockField({ name: 'name', path: '/children/name', type: 'string', order: 2 }),
          ]);
        }));
    });

    describe('context slicer', () => {
      it('should give empty context pre-wrapper', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.repeatContextSlicer()([ 0, 1, 2, 3, 4, 5 ]).should.eql([]);
        }));

      it('should give empty context on root', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.repeatContextSlicer()([ 0, 1, 2, 3, 4, 5 ]).should.eql([]);
        }));

      it('should give empty context on root fields', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.push('name');
          stack.repeatContextSlicer()([ 0, 1, 2, 3, 4, 5 ]).should.eql([]);
        }));

      it('should give empty context on root structures', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.push('children');
          stack.repeatContextSlicer()([ 0, 1, 2, 3, 4, 5 ]).should.eql([]);
        }));

      it('should give repeat context on repeat fields', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.push('children');
          stack.push('child');
          stack.push('name');
          stack.repeatContextSlicer()([ 0, 1, 2, 3, 4, 5 ]).should.eql([ 0, 1 ]);
        }));

      it('should give repeat context on repeat structures', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.push('children');
          stack.push('child');
          stack.push('toys');
          stack.repeatContextSlicer()([ 0, 1, 2, 3, 4, 5 ]).should.eql([ 0, 1 ]);
        }));

      it('should give parent context on repeat repeats', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.push('children');
          stack.push('child');
          stack.push('toys');
          stack.push('toy');
          stack.repeatContextSlicer()([ 0, 1, 2, 3, 4, 5 ]).should.eql([ 0, 1 ]);
        }));

      it('should give repeat context on repeat repeat fields', () => fieldsFor(testData.forms.doubleRepeat)
        .then((fields) => {
          const stack = new SchemaStack(fields);
          stack.push('data');
          stack.push('children');
          stack.push('child');
          stack.push('toys');
          stack.push('toy');
          stack.push('name');
          stack.repeatContextSlicer()([ 0, 1, 2, 3, 4, 5 ]).should.eql([ 0, 1, 2, 3 ]);
        }));
    });
  });

  describe('sanitizeFieldsForOdata', () => {
    const sanitizeXml = `<h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
  <h:head>
    <h:title>Sanitize</h:title>
    <model>
      <instance>
        <data id="sanitize">
          <q1.8>
            <17/>
          </q1.8>
          <4.2/>
        </data>
      </instance>

      <bind nodeset="/data/q1.8/17" type="string" readonly="true()" calculate="concat('uuid:', uuid())"/>
      <bind nodeset="/data/4.2" type="number"/>
    </model>

  </h:head>
  <h:body>
    <input ref="/data/4.2">
      <label>What is your age?</label>
    </input>
  </h:body>
</h:html>`;

    it('should sanitize names', () => fieldsFor(sanitizeXml)
      .then((fields) => {
        sanitizeFieldsForOdata(fields).map((field) => field.name)
          .should.eql([ 'q1_8', '_17', '_4_2' ]);
      }));

    it('should sanitize paths', () => fieldsFor(sanitizeXml)
      .then((fields) => {
        sanitizeFieldsForOdata(fields).map((field) => field.path)
          .should.eql([ '/q1_8', '/q1_8/_17', '/_4_2' ]);
      }));
  });

  describe('expectedFormAttachments', () => {
    it('should find secondary external instance srcs', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <age/>
                  <hometown/>
                </data>
              </instance>
              <instance id="mydata" src="jr://file/mydata.csv"/>
              <instance id="seconddata" src="jr://file-csv/seconddata.csv"/>
              <bind nodeset="/data/name" type="string"/>
              <bind type="int" nodeset="/data/age"/>
              <bind nodeset="/data/hometown" type="select1"/>
            </model>
          </h:head>
        </h:html>`;
      return expectedFormAttachments(xml).then((attachments) => {
        attachments.should.eql([
          { type: 'file', name: 'mydata.csv' },
          { type: 'file', name: 'seconddata.csv' }
        ]);
      });
    });

    it('should ignore broken external instance srcs', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <age/>
                  <hometown/>
                </data>
              </instance>
              <instance id="mydata" src="coolfile.xls"/>
              <instance id="seconddata" src="jr://files/seconddata.csv"/>
              <instance id="thirddata" src="jr://file/goodfile.csv"/>
              <instance id="fourthdata" src="jr://file/path/to/nestedfile.csv"/>
              <instance id="fourthdata" src="jr://audio/mispathed.csv"/>
              <bind nodeset="/data/name" type="string"/>
              <bind type="int" nodeset="/data/age"/>
              <bind nodeset="/data/hometown" type="select1"/>
            </model>
          </h:head>
        </h:html>`;
      return expectedFormAttachments(xml).then((attachments) => {
        attachments.should.eql([
          { type: 'file', name: 'goodfile.csv' },
          { type: 'file', name: 'mispathed.csv' }
        ]);
      });
    });

    it('should find media label files', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <age/>
                  <hometown/>
                </data>
              </instance>
              <bind nodeset="/data/name" type="string"/>
              <bind type="int" nodeset="/data/age"/>
              <bind nodeset="/data/hometown" type="select1"/>
              <itext>
                <translation default="true()" lang="en">
                  <text id="/data/name:label">
                    <value form="image">jr://images/name.jpg</value>
                  </text>
                  <text id="/data/age:label">
                    <value form="audio">jr://audio/age.mp3</value>
                  </text>
                  <text id="/data/hometown:label">
                    <value form="video">jr://video/hometown.mp4</value>
                  </text>
                </translation>
              </itext>
            </model>
          </h:head>
        </h:html>`;
      return expectedFormAttachments(xml).then((attachments) => {
        attachments.should.eql([
          { type: 'image', name: 'name.jpg' },
          { type: 'audio', name: 'age.mp3' },
          { type: 'video', name: 'hometown.mp4' }
        ]);
      });
    });

    it('should interpret big-image as image and ignore other media form types', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <age/>
                  <hometown/>
                </data>
              </instance>
              <bind nodeset="/data/name" type="string"/>
              <bind type="int" nodeset="/data/age"/>
              <bind nodeset="/data/hometown" type="select1"/>
              <itext>
                <translation default="true()" lang="en">
                  <text id="/data/name:label">
                    <value form="big-image">jr://images/name.jpg</value>
                  </text>
                  <text id="/data/age:label">
                    <value form="something">jr://something/age.mp3</value>
                  </text>
                  <text id="/data/hometown:label">
                    <value form="file">jr://file/hometown.mp4</value>
                  </text>
                </translation>
              </itext>
            </model>
          </h:head>
        </h:html>`;
      return expectedFormAttachments(xml).then((attachments) => {
        attachments.should.eql([ { type: 'image', name: 'name.jpg' } ]);
      });
    });

    it('should find media default values from the instance', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <picture>jr://images/default.jpg</picture>
                  <photo>jr://images/default2.jpg</photo>
                  <age>18</age>
                </data>
              </instance>
              <bind nodeset="/data/name" type="string"/>
              <bind type="binary" nodeset="/data/picture"/>
              <bind type="binary" nodeset="/data/photo"/>
              <bind nodeset="/data/age" type="number"/>
            </model>
          </h:head>
        </h:html>`;
      return expectedFormAttachments(xml).then((attachments) => {
        attachments.should.eql([
          { type: 'image', name: 'default.jpg' },
          { type: 'image', name: 'default2.jpg' }
        ]);
      });
    });

    it('should detect the need for itemsets.csv', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <age/>
                  <hometown/>
                </data>
              </instance>
              <bind nodeset="/data/name" type="string"/>
              <bind type="int" nodeset="/data/age"/>
              <bind nodeset="/data/hometown" type="select1"/>
            </model>
          </h:head>
          <h:body>
            <input query="instance('counties')/root/item[state=/select_one_external1/state ]" ref="/select_one_external1/county">
              <label ref="jr:itext('/select_one_external1/county:label')"/>
            </input>
          </h:body>
        </h:html>`;
      return expectedFormAttachments(xml).then((attachments) => {
        attachments.should.eql([{ type: 'file', name: 'itemsets.csv' }]);
      });
    });

    it('should deduplicate identical (name, type) pairs', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <age/>
                  <hometown/>
                </data>
              </instance>
              <bind nodeset="/data/name" type="string"/>
              <bind type="int" nodeset="/data/age"/>
              <bind nodeset="/data/hometown" type="select1"/>
              <itext>
                <translation default="true()" lang="en">
                  <text id="/data/name:label">
                    <value form="image">jr://images/name.jpg</value>
                  </text>
                  <text id="/data/age:label">
                    <value form="image">jr://images/name.jpg</value>
                  </text>
                  <text id="/data/hometown:label">
                    <value form="video">jr://video/hometown.mp4</value>
                  </text>
                </translation>
              </itext>
            </model>
          </h:head>
        </h:html>`;
      return expectedFormAttachments(xml).then((attachments) => {
        attachments.should.eql([
          { type: 'image', name: 'name.jpg' },
          { type: 'video', name: 'hometown.mp4' }
        ]);
      });
    });

    it('should not deduplicate identical names with different types', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model>
              <instance>
                <data id="form">
                  <name/>
                  <age/>
                  <hometown/>
                </data>
              </instance>
              <bind nodeset="/data/name" type="string"/>
              <bind type="int" nodeset="/data/age"/>
              <bind nodeset="/data/hometown" type="select1"/>
              <itext>
                <translation default="true()" lang="en">
                  <text id="/data/name:label">
                    <value form="image">jr://images/name.file</value>
                  </text>
                  <text id="/data/age:label">
                    <value form="audio">jr://images/name.file</value>
                  </text>
                  <text id="/data/hometown:label">
                    <value form="video">jr://video/hometown.mp4</value>
                  </text>
                </translation>
              </itext>
            </model>
          </h:head>
        </h:html>`;
      return expectedFormAttachments(xml).then((attachments) => {
        attachments.should.eql([
          { type: 'image', name: 'name.file' },
          { type: 'audio', name: 'name.file' },
          { type: 'video', name: 'hometown.mp4' }
        ]);
      });
    });

    it('should detect primitive search() appearances', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model/>
          </h:head>
          <h:body>
            <select1 appearance="search('fileone')"/>
            <select appearance="search('filetwo.csv')"/>
            <select appearance="search('filethree', 1)"/>
            <select1 appearance="search( 'filefour' , 2)"/>
            <select1 appearance="search(&quot;filefive&quot;, 3, 4)"/>
          </h:body>
        </h:html>`;
      return expectedFormAttachments(xml).then((attachments) => {
        attachments.should.eql([
          { type: 'file', name: 'fileone.csv' },
          { type: 'file', name: 'filetwo.csv' },
          { type: 'file', name: 'filethree.csv' },
          { type: 'file', name: 'filefour.csv' },
          { type: 'file', name: 'filefive.csv' }
        ]);
      });
    });

    it('should ignore goofy or advanced search() appearances', () => {
      const xml = `
        <?xml version="1.0"?>
        <h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
          <h:head>
            <model/>
          </h:head>
          <h:body>
            <select1 appearance="search('fileone   ')"/>
            <select appearance="search(/data/path/to/dynamic)"/>
            <select appearance="search(' filethree')"/>
            <select1 appearance="search(' filefour.csv ' , 2)"/>
          </h:body>
        </h:html>`;
      return expectedFormAttachments(xml).then((attachments) => {
        attachments.should.eql([]);
      });
    });
  });

  describe('public key injection', () => {
    it('it should successfully inject into self-closing tags', () => {
      const xml = `
<?xml version="1.0"?>
<h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
  <h:head>
    <model>
      <instance>
        <data id="form">
          <name/>
        </data>
      </instance>
      <bind nodeset="/data/name" type="string"/>
      <submission action="https://opendatakit.org/custom-action"/>
    </model>
  </h:head>
</h:html>`;

      return injectPublicKey(xml, 'mybase64key').then((result) => result.should.equal(`
<?xml version="1.0"?>
<h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
  <h:head>
    <model>
      <instance>
        <data id="form">
          <name/>
        </data>
      </instance>
      <bind nodeset="/data/name" type="string"/>
      <submission action="https://opendatakit.org/custom-action" base64RsaPublicKey="mybase64key"/>
    </model>
  </h:head>
</h:html>`));
    });

    it('it should successfully inject into whitespacey self-closing tags', () => {
      const xml = `
<?xml version="1.0"?>
<h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
  <h:head>
    <model>
      <instance>
        <data id="form">
          <name/>
        </data>
      </instance>
      <bind nodeset="/data/name" type="string"/>
      <submission action="https://opendatakit.org/custom-action" /  
      >
    </model>
  </h:head>
</h:html>`;

      return injectPublicKey(xml, 'mybase64key').then((result) => result.should.equal(`
<?xml version="1.0"?>
<h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
  <h:head>
    <model>
      <instance>
        <data id="form">
          <name/>
        </data>
      </instance>
      <bind nodeset="/data/name" type="string"/>
      <submission action="https://opendatakit.org/custom-action"  base64RsaPublicKey="mybase64key"/  
      >
    </model>
  </h:head>
</h:html>`));
    });

    it('it should successfully inject into model tags', () => {
      const xml = `
<?xml version="1.0"?>
<h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
  <h:head>
    <model>
      <instance>
        <data id="form">
          <name/>
        </data>
      </instance>
      <bind nodeset="/data/name" type="string"/>
    </model>
  </h:head>
</h:html>`;

      return injectPublicKey(xml, 'mybase64key').then((result) => result.should.equal(`
<?xml version="1.0"?>
<h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
  <h:head>
    <model>
      <instance>
        <data id="form">
          <name/>
        </data>
      </instance>
      <bind nodeset="/data/name" type="string"/>
    <submission base64RsaPublicKey="mybase64key"/></model>
  </h:head>
</h:html>`));
    });

    it('it should fail out on broken xforms', () => {
      const xml = `
<?xml version="1.0"?>
<h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
  <h:head>
  </h:head>
</h:html>`;

      return injectPublicKey(xml, 'mybase64key')
        .should.be.rejected()
        .then((p) => { p.problemCode.should.equal(400.1); });
    });
  });

  describe('addVersionSuffix', () => {
    it('should add a version attribute', () =>
      addVersionSuffix(testData.forms.simple, 'testtest').then((result) => result.should.equal(`<h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
  <h:head>
    <h:title>Simple</h:title>
    <model>
      <instance>
        <data id="simple" version="testtest">
          <meta>
            <instanceID/>
          </meta>
          <name/>
          <age/>
        </data>
      </instance>

      <bind nodeset="/data/meta/instanceID" type="string" readonly="true()" calculate="concat('uuid:', uuid())"/>
      <bind nodeset="/data/name" type="string"/>
      <bind nodeset="/data/age" type="int"/>
    </model>

  </h:head>
  <h:body>
    <input ref="/data/name">
      <label>What is your name?</label>
    </input>
    <input ref="/data/age">
      <label>What is your age?</label>
    </input>
  </h:body>
</h:html>`)));

    it('should suffix an existing version attribute', () =>
      addVersionSuffix(testData.forms.simple2, 'testtest').then((result) => result.should.equal(`<h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
  <h:head>
    <h:title>Simple 2</h:title>
    <model>
      <instance>
        <data id="simple2" version="2.1testtest">
          <meta>
            <instanceID/>
          </meta>
          <name/>
          <age/>
        </data>
      </instance>

      <bind nodeset="/data/meta/instanceID" type="string" readonly="true()" calculate="concat('uuid:', uuid())"/>
      <bind nodeset="/data/name" type="string"/>
      <bind nodeset="/data/age" type="int"/>
    </model>

  </h:head>
  <h:body>
    <input ref="/data/name">
      <label>What is your name?</label>
    </input>
    <input ref="/data/age">
      <label>What is your age?</label>
    </input>
  </h:body>
</h:html>`)));

    it('should suffix an existing namespaced version attribute', () =>
      addVersionSuffix(testData.forms.simple2.replace('version', 'orx:version'), 'testtest').then((result) => result.should.equal(`<h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
  <h:head>
    <h:title>Simple 2</h:title>
    <model>
      <instance>
        <data id="simple2" orx:version="2.1testtest">
          <meta>
            <instanceID/>
          </meta>
          <name/>
          <age/>
        </data>
      </instance>

      <bind nodeset="/data/meta/instanceID" type="string" readonly="true()" calculate="concat('uuid:', uuid())"/>
      <bind nodeset="/data/name" type="string"/>
      <bind nodeset="/data/age" type="int"/>
    </model>

  </h:head>
  <h:body>
    <input ref="/data/name">
      <label>What is your name?</label>
    </input>
    <input ref="/data/age">
      <label>What is your age?</label>
    </input>
  </h:body>
</h:html>`)));

    it('should fail out unless the primary instance has an inner tag', () =>
      addVersionSuffix(`<h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
  <h:head>
    <h:title>Simple</h:title>
    <model>
      <instance>
      </instance>
      <instance>
        <data id="notprimary">
          <meta>
            <instanceID/>
          </meta>
          <name/>
          <age/>
        </data>
      </instance>

      <bind nodeset="/data/meta/instanceID" type="string" readonly="true()" calculate="concat('uuid:', uuid())"/>
      <bind nodeset="/data/name" type="string"/>
      <bind nodeset="/data/age" type="int"/>
    </model>

  </h:head>
  <h:body>
    <input ref="/data/name">
      <label>What is your name?</label>
    </input>
    <input ref="/data/age">
      <label>What is your age?</label>
    </input>
  </h:body>
</h:html>`, '-testtest').should.be.rejected().then((p) => p.problemCode.should.equal(400.1)));

    it('should fail out if there is no instance', () =>
      addVersionSuffix(`<h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
  <h:head>
    <h:title>Simple</h:title>
    <model>
    </model>
  </h:head>
</h:html>`, '-testtest').should.be.rejected().then((p) => p.problemCode.should.equal(400.1)));
  });

  describe('setVersion', () => {
    it('should add a version attribute', () =>
      setVersion(testData.forms.simple, 'testtest').then((result) => result.should.equal(`<h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
  <h:head>
    <h:title>Simple</h:title>
    <model>
      <instance>
        <data id="simple" version="testtest">
          <meta>
            <instanceID/>
          </meta>
          <name/>
          <age/>
        </data>
      </instance>

      <bind nodeset="/data/meta/instanceID" type="string" readonly="true()" calculate="concat('uuid:', uuid())"/>
      <bind nodeset="/data/name" type="string"/>
      <bind nodeset="/data/age" type="int"/>
    </model>

  </h:head>
  <h:body>
    <input ref="/data/name">
      <label>What is your name?</label>
    </input>
    <input ref="/data/age">
      <label>What is your age?</label>
    </input>
  </h:body>
</h:html>`)));

    it('should replace an existing version attribute', () =>
      setVersion(testData.forms.simple2, 'testtest').then((result) => result.should.equal(`<h:html xmlns="http://www.w3.org/2002/xforms" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:jr="http://openrosa.org/javarosa">
  <h:head>
    <h:title>Simple 2</h:title>
    <model>
      <instance>
        <data id="simple2" version="testtest">
          <meta>
            <instanceID/>
          </meta>
          <name/>
          <age/>
        </data>
      </instance>

      <bind nodeset="/data/meta/instanceID" type="string" readonly="true()" calculate="concat('uuid:', uuid())"/>
      <bind nodeset="/data/name" type="string"/>
      <bind nodeset="/data/age" type="int"/>
    </model>

  </h:head>
  <h:body>
    <input ref="/data/name">
      <label>What is your name?</label>
    </input>
    <input ref="/data/age">
      <label>What is your age?</label>
    </input>
  </h:body>
</h:html>`)));
  });
});

