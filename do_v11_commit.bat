@echo off
cd /d C:\Users\Administrator\Desktop\cyberdudebivash-blog
git add .
git commit -m "GOD LEVEL v11 — Alert Fix, Brand Rebuild, Live Threat Intel sitewide"
git push origin main > push_result.txt 2>&1
echo DONE >> push_result.txt
git log --oneline -3 >> push_result.txt
