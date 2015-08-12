# fanotify-cmd

Use fanotify API to monitor changes/events on files.  Reports on PID
and command line of process generating the event.

## Usage:

usage: [options] &lt;files...&gt;
Options:
	-a:	monitor access
	-m:	monitor modify
	-o:	monitor open
	-r:	monitor close (read)
	-w:	monitor close (write)
