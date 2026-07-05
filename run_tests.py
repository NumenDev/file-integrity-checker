#!/usr/bin/env python3
"""
Testes automatizados do integrity-check.

Cada teste monta um cenário, roda a ferramenta e confere a saída/exit code
esperados. Usa um diretório temporario isolado (INTEGRITY_CHECK_HOME), entao
NAO mexe na baseline real do usuario.

    python run_tests.py
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

TOOL = Path(__file__).with_name("integrity_check.py")
PY = sys.executable

passed = 0
failed = 0


def run(args, home, logs):
    """Roda a ferramenta e devolve (exit_code, stdout+stderr)."""
    env = dict(os.environ, INTEGRITY_CHECK_HOME=str(home))
    proc = subprocess.run(
        [PY, str(TOOL), *args],
        capture_output=True, text=True, env=env,
    )
    return proc.returncode, proc.stdout + proc.stderr


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}   {detail}")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        home = tmp / "db"
        logs = tmp / "logs"
        (logs / "sub").mkdir(parents=True)
        (logs / "syslog").write_text("linha original de log\n")
        (logs / "auth.log").write_text("login aceito para igor\n")
        (logs / "sub" / "app.log").write_text("app iniciado\n")

        # 1. init cria a baseline
        code, out = run(["init", str(logs)], home, logs)
        check("init retorna 0", code == 0, f"code={code}")
        check("init confirma armazenamento", "stored successfully" in out, out)

        # 2. check limpo -> Unmodified, exit 0
        code, out = run(["check", str(logs)], home, logs)
        check("check limpo retorna 0", code == 0, f"code={code}")
        check("check limpo diz Unmodified", "Status: Unmodified" in out, out)

        # 3. arquivo unico intacto
        code, out = run(["check", str(logs / "auth.log")], home, logs)
        check("arquivo intacto: exit 0", code == 0, f"code={code}")
        check("arquivo intacto: Unmodified", out.strip() == "Status: Unmodified", out)

        # 4. adultera um log -> deve detectar
        (logs / "syslog").write_text("linha ADULTERADA pelo atacante\n")
        code, out = run(["check", str(logs / "syslog")], home, logs)
        check("log adulterado: exit 1", code == 1, f"code={code}")
        check("log adulterado: Hash mismatch", "Hash mismatch" in out, out)

        # 5. diretorio com modificado + novo + ausente
        (logs / "novo.log").write_text("nao estava na baseline\n")
        (logs / "sub" / "app.log").unlink()
        code, out = run(["check", str(logs)], home, logs)
        check("dir adulterado: exit 1", code == 1, f"code={code}")
        check("detecta MODIFIED", "MODIFIED" in out, out)
        check("detecta NEW", "NEW" in out, out)
        check("detecta MISSING", "MISSING" in out, out)

        # 6. update aceita a mudanca legitima
        code, out = run(["update", str(logs / "syslog")], home, logs)
        check("update: exit 0", code == 0, f"code={code}")
        code, out = run(["check", str(logs / "syslog")], home, logs)
        check("apos update: Unmodified", "Status: Unmodified" in out, out)

        # 7. check sem baseline -> erro exit 2
        code, out = run(["check", str(logs)], tmp / "vazio", logs)
        check("sem baseline: exit 2", code == 2, f"code={code}")
        check("sem baseline: mensagem clara", "Run 'init'" in out, out)

        # 8. banco adulterado (HMAC invalido) -> exit 2
        db = home / "hashes.json"
        db.write_text(db.read_text().replace('"size"', '"SIZE"'))
        code, out = run(["check", str(logs)], home, logs)
        check("banco adulterado: exit 2", code == 2, f"code={code}")
        check("banco adulterado: SECURITY WARNING", "SECURITY WARNING" in out, out)

        # 9. init reconstroi mesmo com banco corrompido
        db.write_text("lixo que nao e json {{{")
        code, out = run(["init", str(logs)], home, logs)
        check("init reconstroi banco corrompido: exit 0", code == 0, f"code={code}")

        # 10. filtro --pattern
        code, out = run(["check", str(logs), "--pattern", "*.log"], home, logs)
        check("--pattern ignora 'syslog'", "syslog" not in out, out)
        check("--pattern inclui .log", "auth.log" in out, out)

    print(f"\n{passed} passaram, {failed} falharam")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
