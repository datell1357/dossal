#!/usr/bin/env python3
"""Windows용 dossal.exe 빌드 스크립트"""
import subprocess
import sys
import os

print("Windows용 dossal.exe 빌드 중...")

# PyInstaller로 exe 파일 빌드
result = subprocess.run([
    sys.executable, "-m", "PyInstaller",
    "--onefile",
    "--name", "dossal",
    "--clean",
    "dossal.py"
], capture_output=True, text=True)

if result.returncode == 0:
    print("빌드 완료: dist/dossal.exe")
    print("압축: dist/dossal.exe.zip")
else:
    print(f"빌드 실패: {result.stderr}")
    sys.exit(1)

# 압축 파일 생성
if os.path.exists("dist/dossal.exe"):
    subprocess.run(["zip", "-9", "dist/dossal-v15.9-windows.exe.zip", "dist/dossal.exe"])
    print("압축 완료: dist/dossal-v15.9-windows.exe.zip")
