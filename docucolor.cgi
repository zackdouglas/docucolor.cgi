#!/usr/bin/env python

# docucolor.cgi -- CGI script to interpret Xerox DocuColor forensic dot pattern
# Copyright (C) 2005 Electronic Frontier Foundation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
#
#
# Xerox Corporation has no connection with this program and does not
# warrant its correctness.
#
# This program is the result of research by Robert Lee, Seth Schoen, Patrick
# Murphy, Joel Alwen, and Andrew "bunnie" Huang.  For more information, see
# http://www.eff.org/Privacy/printers

import cgi, os, sys
import cgitb; cgitb.enable()

print "Content-type: text/html"
print
form = cgi.FieldStorage()
print """<html><head>
<title>DocuColor pattern interpretation</title>
</head>
<body>
<h2>DocuColor pattern interpretation</h2>
<hr />"""

def print_matrix():
    # Print the matrix of dots on standard output.
    print "<pre>"
    print "           111111"
    print "  123456789012345"
    for y in range(7, -1, -1):
        line = ""
        for x in range(1, 16):
            if dots[(x,y)]: line = line + "o"
            else: line = line + " "
        print y, line
    print "</pre>"

def column_value(col):
    # Extract and decode the value of the indicated column.
    total = 0
    for y in range(6, -1, -1):
        total = total + dots[(col, y)] * 2**y
    return total

def footer():
    if os.environ.has_key("HTTP_REFERER"):
        r = os.environ["HTTP_REFERER"]
        if r:
            print '<p><a href="%s">Back to referring page</a></p>' % r
        print "</body></html>"
        sys.exit(0)

dots = {}
for x in range(1, 16):
    for y in range(0,8):
        dots[(x,y)] = form.has_key("%i,%i" % (x,y))

# Step 1: display disclaimer and output
print "<p>This is an interpretation of the following dot pattern:</p>"

print_matrix()

print """<p>This interpretation is based on reverse engineering, and may not
be complete or current for every DocuColor model version.  Xerox
Corporation has no connection with this program, and does not warrant
its correctness.</p><hr />"""

if not 1 in dots.values():
    print "<p>This pattern is <strong>empty</strong> and cannot be interpreted.</p>"
    footer()

# Step 2: verify row parity
bad_rows = []

# don't check row 7 because it is expected to have even parity
for row in range(6, -1, -1):
    p = 0
    for col in range(1, 16):
        p = (p + dots[(col, row)]) % 2
    if p == 0:
        print "Parity mismatch for row %i.<br />" % row
        bad_rows = bad_rows + [row]

# Step 3: verify column parity
bad_cols = []
for col in range(1, 16):
    p = 0
    for row in range(7, -1, -1):
        p = (p + dots[(col, row)]) % 2
    if p == 0:
        print "Parity mismatch for column %i.<br />" % col
        bad_cols = bad_cols + [col]

# Step 4: try to correct input errors
correction = 0
if bad_rows or bad_cols:
    if len(bad_cols) == 1 and len(bad_rows) == 0:
        # error in column parity row!
        # We could be more stringent about this by also verifying the
        # row 7 has even parity, but the case that's affected by this
        # is extraordinarily rare (under bizarre circumstances, we
        # incorrectly conclude that an uncorrectable error is
        # correctable).
        print "Correctable error in row 7 (column parity) at column", bad_cols[0]
        dots[(bad_cols[0], 7)] = not dots[(bad_cols[0], 7)]
        correction = 1
    if len(bad_cols) == 1 and len(bad_rows) == 1:
        # correctable error (single row error, single column error)
        print "Correctable error at row", bad_rows[0], "and col", bad_cols[0]
        dots[(bad_cols[0], bad_rows[0])] = not dots[(bad_cols[0], bad_rows[0])]
        correction = 1
    if len(bad_cols) > 1 or len(bad_rows) > 1:
        # multiple rows or multiple columns in error
        print "Errors could not be corrected!  Using erroneous matrix."
    if len(bad_cols) > 3 or len(bad_rows) > 3:
        print "<p><strong>There are numerous errors here; you probably"
        print "did not enter a genuine DocuColor matrix, or used a"
        print "matrix we don't know how to decode.  The content of"
        print "this interpretation is unlikely to be"
        print "meaningful.</strong></p>"
    print "<br>"
else:
    print "Row and column parity verified correctly."

if correction:
    print "<p>Making correction and processing corrected matrix:</p>"
    print_matrix()
    print "<hr />"

# Step 5: decode serial number (with and without column 14)

print "<p>Printer serial number: %02i%02i%02i [or %02i%02i%02i%02i]</p>" % (tuple(map(column_value, (13, 12, 11))) + tuple(map(column_value, (14, 13, 12, 11))))

# Step 6: decode date and time

# Year: guessing about Y2K, for lack of any relevant evidence
year = column_value(8)
if year < 70 or year > 99:
    year = year + 2000
else:
    year = year + 1900

# Month
month_names = ["(no month specified)", "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
try:
    month = month_names[column_value(7)]
except IndexError:
    month = "(<strong>invalid</strong> month %i)" % column_value(8)

# Day
day = column_value(6)
if day == 0:
    day = "(no day specified)"
elif day > 31:
    day = "(<strong>invalid</strong> day %i)" % day

print "<p>Date: %s %s, %s</p>" % (str(month), str(day), str(year))

hour = column_value(5)
minute = column_value(2)

print "<p>Time: %02i:%02i</p>" % (hour, minute)

# Step 7: decode unknown column 15

print "<p>"
print "Column 15 value: %i" % column_value(15)

footer()
