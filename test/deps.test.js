'use strict';
// Lectura de dependencias de cada ecosistema que se consulta en OSV.dev.
const test = require('node:test');
const assert = require('node:assert/strict');
const fx = require('./helpers/fixtures');
const { collect } = require('../lib/deps');

const FILES = {
  'Cargo.lock': 'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.190"\nsource = "registry"\n\n[[package]]\nname = "tokio"\nversion = "1.33.0"\n',
  'py/poetry.lock': '[[package]]\nname = "pyyaml"\nversion = "5.3"\ndescription = "x"\n',
  'py/Pipfile.lock': JSON.stringify({ default: { jinja2: { version: '==2.10' }, requests: { version: '*' } }, develop: {} }),
  'php/composer.lock': JSON.stringify({ packages: [{ name: 'guzzlehttp/guzzle', version: 'v7.4.0' }, { name: 'acme/x', version: 'dev-main' }], 'packages-dev': [] }),
  'rb/Gemfile.lock': 'GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.13.0-x86_64-linux)\n      racc (~> 1.4)\n    rails (6.1.0)\n\nPLATFORMS\n  ruby\n',
  'js/yarn.lock': '# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.22.5"\n  resolved "https://registry.yarnpkg.com/x"\n\nlodash@^4.17.0:\n  version "4.17.15"\n',
  'java/pom.xml': '<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency><dependency><groupId>a</groupId><artifactId>b</artifactId><version>${b.version}</version></dependency></dependencies></project>',
  'java/build.gradle': "dependencies {\n  implementation 'com.fasterxml.jackson.core:jackson-databind:2.9.8'\n}\n",
  'js/package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/esbuild': { version: '0.19.0', hasInstallScript: true }, 'node_modules/left-pad': { version: '1.3.0' } } }),
};

test('dependencias: lee los lockfiles de todos los ecosistemas', (t) => {
  const dir = fx.write(fx.tmpDir('deps'), FILES);
  t.after(() => fx.rm(dir));
  const { pkgs, threats } = collect(dir, Object.keys(FILES));
  const has = (eco, name, version) => assert.ok(pkgs.some((p) => p.ecosystem === eco && p.name === name && p.version === version), `${eco} ${name}@${version}`);
  has('crates.io', 'serde', '1.0.190');
  has('crates.io', 'tokio', '1.33.0');
  has('PyPI', 'pyyaml', '5.3');
  has('PyPI', 'jinja2', '2.10');
  has('Packagist', 'guzzlehttp/guzzle', '7.4.0');
  has('RubyGems', 'nokogiri', '1.13.0');
  has('RubyGems', 'rails', '6.1.0');
  has('npm', '@babel/core', '7.22.5');
  has('npm', 'lodash', '4.17.15');
  has('Maven', 'org.apache.logging.log4j:log4j-core', '2.14.1');
  has('Maven', 'com.fasterxml.jackson.core:jackson-databind', '2.9.8');
  assert.ok(!pkgs.some((p) => p.name === 'racc'), 'las dependencias anidadas del Gemfile.lock no se duplican');
  assert.ok(!pkgs.some((p) => p.name === 'acme/x'), 'las ramas dev-* no tienen versión');
  assert.equal(pkgs.find((p) => p.name === 'a:b').version, null, 'versión con propiedad: sin consultar');
  const s = threats.find((x) => x.rule === 'dep-install-scripts');
  assert.ok(s && /esbuild/.test(s.snippet) && !/left-pad/.test(s.snippet));
});
