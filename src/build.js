import * as fs from 'fs';
import ts from 'typescript';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const __distdir = path.resolve(__dirname, '../dist');

const shellScriptContent = fs.readFileSync(path.join(__dirname, 'getomni.sh'), 'utf8').toString();

let workerTemplate = fs.readFileSync(path.join(__dirname, 'index.ts'), 'utf8');
workerTemplate = workerTemplate.replace('\'SHELL_SCRIPT_CONTENT\'', JSON.stringify(shellScriptContent));

if (!fs.existsSync(__distdir)){
  fs.mkdirSync(__distdir, { recursive: true });
}
fs.writeFileSync(path.join(__distdir, 'index.ts'), workerTemplate);

// Now compile the TypeScript
const result = ts.transpileModule(workerTemplate, {
  compilerOptions: { module: ts.ModuleKind.ESNext }
});

fs.writeFileSync(path.join(__distdir, 'index.js'), result.outputText);
