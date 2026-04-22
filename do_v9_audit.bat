@echo off
cd /d "C:\Users\Administrator\Desktop\cyberdudebivash-blog"
echo === GIT LOG === > v9_audit.txt
git log --oneline -8 >> v9_audit.txt
echo === GIT STATUS === >> v9_audit.txt
git status --short >> v9_audit.txt
echo === UNTRACKED/MODIFIED === >> v9_audit.txt
git diff --name-only >> v9_audit.txt
echo AUDIT_DONE >> v9_audit.txt
