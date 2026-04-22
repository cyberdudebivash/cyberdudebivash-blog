@echo off
SET GIT="C:\Program Files\Git\cmd\git.exe"
cd /d "C:\Users\Administrator\Desktop\cyberdudebivash-blog"

echo [0/5] Removing stale lock files...
del /f .git\index.lock 2>nul
del /f .git\index 2>nul

echo [1/5] Resetting index...
%GIT% reset HEAD

echo [2/5] Staging all changes...
%GIT% add products.html
%GIT% add monetization.js
%GIT% add api.html
%GIT% add sitemap.xml
%GIT% add index.html
%GIT% add intelligence.html
%GIT% add pricing.html
%GIT% add archive.html
%GIT% add do_push_v6.bat
%GIT% add posts\

echo [3/5] Committing...
%GIT% commit -m "GOD LEVEL v6: products.html marketplace, monetization.js on ALL 15 pages, products nav"

echo [4/5] Pushing to origin/main...
%GIT% push origin main

echo [5/5] Verifying...
%GIT% log --oneline -3

echo DONE > push_v6_result.txt
%GIT% log --oneline -1 >> push_v6_result.txt
