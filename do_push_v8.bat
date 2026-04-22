@echo off
SET GIT="C:\Program Files\Git\cmd\git.exe"
cd /d "C:\Users\Administrator\Desktop\cyberdudebivash-blog"

echo [0] Clean locks...
del /f .git\index.lock 2>nul

echo [1] Stage everything...
%GIT% add ai-monetization-engine.js
%GIT% add sitemap.xml
%GIT% add enterprise.html
%GIT% add leads.html
%GIT% add cve\
%GIT% add threat\
%GIT% add attack\
%GIT% add posts\
%GIT% add index.html
%GIT% add intelligence.html
%GIT% add pricing.html
%GIT% add archive.html
%GIT% add api.html
%GIT% add products.html
%GIT% add conversion-engine.js
%GIT% add seo-engine.js

echo [2] Commit...
%GIT% commit -m "GOD LEVEL v8: ai-monetization-engine.js intent+pricing+scarcity, 27 programmatic CVE/threat/attack pages, enterprise closing system upgraded"

echo [3] Push...
%GIT% push origin main

echo [4] Verify...
%GIT% log --oneline -3
echo DONE_V8 > push_v8_result.txt
%GIT% log --oneline -1 >> push_v8_result.txt
