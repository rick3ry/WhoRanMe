# WhoRanMe
forensics: find out how a program is being invoked

A virus left something on my machine that would periodically run. I wanted to find out what was running the program, so I made this.

Rename the program that is being run and replace it with this program.  This program will log as much information as it can about who called it.

Example:
 - used video capture to catch a window popping up
 - observed pathname in window
 - $ attrib -S -H pathname
 - $ ren pathname pathname.bad
 - $ xcopy WhoRanMe.exe pathname
 - $ attrib +S +H pathname
 - $ type %USERPROFILE%\ppidout.txt
 
If the 'S' and 'H' attributes are not already set for pathname, both attrib commands should be ignored.
