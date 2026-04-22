@echo off
SET GIT="C:\Program Files\Git\cmd\git.exe"
cd /d "C:\Users\Administrator\Desktop\cyberdudebivash-blog"

echo [0] Clean locks...
del /f .git\index.lock 2>nul

echo [1] Stage all new + modified files...
%GIT% add conversion-engine.js
%GIT% add seo-engine.js
%GIT% add enterprise.html
%GIT% add leads.html
%GIT% add products.html
%GIT% add api.html
%GIT% add index.html
%GIT% add intelligence.html
%GIT% add pricing.html
%GIT% add archive.html
%GIT% add sitemap.xml
%GIT% add posts\

echo [2] Commit...
%GIT% commit -m "GOD LEVEL v7: conversion-engine.js A/B+tracking, seo-engine.js schema+linking, enterprise.html ROI page, leads.html funnel, ALL 18 pages wired"

echo [3] Push...
%GIT% push origin main

echo [4] Verify...
%GIT% log --oneline -3
echo DONE_V7 > push_v7_result.txt
%GIT% log --oneline -1 >> push_v7_result.txt
