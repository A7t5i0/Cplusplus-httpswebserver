# C++ webserver
Webserver written in C++

Features:

-Supports file uploads

-Auto detect files (html, js, png, jpeg, jpg, mp4, mov, php etc)

-Filenames are turned into urls (after upoading eg filename you can use protocol://ip:port/filename to view them in browser)

-Supports ipv4 and ipv6

-uses SSL

-Multithreading (fork)

-Checks for symbols " ' ./ to prevent exposing /etc/passwd

-Checks for possible commands such as sudo and cat to prevent commands being run by bad actors.

Compiled with:

g++ -g main.cpp -o server -Wformat-truncation -Wformat-overflow -Wextra -lssl -lcrypto

Use:

./server
