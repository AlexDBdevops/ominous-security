'use strict';
// Cada regla tiene su ficha explicativa, y las reglas de Java y PHP saltan con su patrón
// (y no con el código correcto equivalente).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const fx = require('./helpers/fixtures');
const { vulnRules, threatRules } = require('../lib/rules');
const { explain } = require('../lib/explain');
const { analyzeTree, applyAutoFixes } = require('../lib/analyzer');

test('todas las reglas tienen una ficha explicativa propia', () => {
  const miss = [...vulnRules.map((r) => [r.id, 'vuln']), ...threatRules.map((r) => [r.id, 'threat'])]
    .filter(([id, kind]) => explain(id, kind).name === 'Patrón sospechoso').map(([id]) => id);
  assert.deepEqual(miss, []);
  const ids = [...vulnRules, ...threatRules].map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, 'sin ids repetidos');
});

const BAD = {
  'src/Db.java': 'ResultSet rs = st.executeQuery("SELECT * FROM u WHERE id=" + id);',
  'src/Trust.java': 'public void checkServerTrusted(X509Certificate[] c, String a) {}',
  'src/Host.java': 'conn.setHostnameVerifier((h, s) -> true);',
  'src/Tok.java': 'String token = Long.toString(new Random().nextLong());',
  'src/Sec.java': 'http.csrf().disable();',
  'src/Xml.java': 'DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();',
  'src/Run.java': 'Runtime.getRuntime().exec("ping " + host);',
  'web/a.php': '<?php assert($_GET["x"]);',
  'web/b.php': '<?php echo preg_replace("/x/e", $r, $s);',
  'web/c.php': '<?php extract($_POST);',
  'web/d.php': '<?php echo $_GET["name"];',
  'web/e.php': '<?php curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);',
  'web/f.php': '<?php curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);',
  'web/g.php': '<?php $h = md5($password);',
  'web/h.php': '<?php ini_set("display_errors", "1");',
};
const EXPECT = ['java-sqli', 'java-tls', 'java-hostname-tls', 'java-random', 'spring-csrf', 'java-xxe', 'java-cmd', 'php-assert-eval', 'php-preg-eval', 'php-extract', 'php-xss', 'php-tls', 'php-host-tls', 'php-weakhash', 'php-debug'];

const GOOD = {
  'src/Db.java': 'PreparedStatement ps = c.prepareStatement("SELECT * FROM u WHERE id=?");',
  'src/Tok.java': 'String token = Long.toString(new SecureRandom().nextLong());',
  'web/d.php': '<?php echo htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8");',
  'web/e.php': '<?php curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);',
  'web/g.php': '<?php $h = password_hash($password, PASSWORD_DEFAULT);',
};

test('reglas de Java y PHP', async (t) => {
  const bad = fx.write(fx.tmpDir('lang'), BAD);
  const good = fx.write(fx.tmpDir('lang-ok'), GOOD);
  t.after(() => { fx.rm(bad); fx.rm(good); });
  const r = await analyzeTree(fs.realpathSync(bad), null);
  const got = new Set(r.vulnerabilities.map((v) => v.rule));
  for (const id of EXPECT) assert.ok(got.has(id), id);
  const ok = await analyzeTree(fs.realpathSync(good), null);
  assert.deepEqual(ok.vulnerabilities.map((v) => v.rule), []);
  // El arreglo automático de cURL deja la verificación activada
  const applied = applyAutoFixes(fs.realpathSync(bad), r.vulnerabilities.filter((v) => v.rule === 'php-tls'));
  assert.equal(applied.length, 1);
  assert.match(fs.readFileSync(`${bad}/web/e.php`, 'utf8'), /CURLOPT_SSL_VERIFYPEER, true/);
});
