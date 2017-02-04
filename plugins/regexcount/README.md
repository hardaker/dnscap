# Regex Counter for dnscap

This plugin searches dns query data for names matching a series of
extensions, counts the hits per second (XXX: make customization
times).  It then reports into the output file the number of times per
second that a name was hit in a file that is passable to gnuplot.

# Example

    # dnscap -g -r test.pcap -P regexcount.so -o test.dat -r gg=google -r dc=doubleclick
    # cat test.dat

    #               gg      dc
	1485531753      3       0
	1485531754      0       0
	1485531755      0       3
	1485531756      0       0
	1485531757      0       0
	1485531758      4       0
	1485531759      1       0
	1485531760      0       0
	1485531761      2       0
	1485531762      0       0
	1485531763      0       0
	1485531764      2       0
	1485531765      0       0
	1485531766      7       0
	1485531767      0       0
	1485531768      0       0
	1485531769      2       0
	1485531770      6       0
	1485531771      1       0
	1485531772      2       0
	1485531773      0       0

# Gnuplot usage

	set terminal png size 1024,1024
	set output "test.png"
	set ylabel "pkts"
	set xlabel "time"
	set timefmt "%s"
	set xdata time
	plot "test.dat" using 1:2 title "google" with lines, "test.dat" using 1:3 title "doubleclick" with lines

