@echo off
cd /d C:\Users\Administrator\Desktop\cyberdudebivash-blog
git add index.html apex-v13.css ai-security/index.html breaking/index.html intel/index.html malware/index.html posts/ 2>> v13_push_log.txt
git add apex-v12.css conversion-engine.js 2>> v13_push_log.txt
git status >> v13_push_log.txt
git commit -m "GOD LEVEL v13 ? Global text visibility upgrade, CYBERDUDEBIVASH ecosystem ad monetization, 5-platform rotating ad carousel, ecosystem sidebar widget, section page ads" >> v13_push_log.txt 2>&1
git push origin main >> v13_push_log.txt 2>&1
echo DONE >> v13_push_log.txt
