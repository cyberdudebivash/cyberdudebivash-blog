@echo off
cd /d C:\Users\Administrator\Desktop\cyberdudebivash-blog
git add .
git commit -m "GOD LEVEL v12 — P0 Fix: Clean rebuild index.html, zero regression, production stable"
git push origin main > push_v12_result.txt 2>&1
echo DONE >> push_v12_result.txt
git log --oneline -4 >> push_v12_result.txt
