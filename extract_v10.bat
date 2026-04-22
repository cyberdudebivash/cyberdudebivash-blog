@echo off
cd /d C:\Users\Administrator\Desktop\cyberdudebivash-blog
git show 4fc14bf:index.html > index_v10_clean.html
echo DONE > extract_done.txt
git log --oneline -1 >> extract_done.txt
