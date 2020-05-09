# Makefile to create a zip archive with submission files

# Files to submit files
HIDDENFILES=file1.data file2.data file3.data file4.data Hiddec.java Hidenc.java 

# Add any additional files with java classes here
HIDDENEXTRAS=

AUTHFILES=.kaka .base.xml

hidden.zip: 
ifeq ("$(wildcard $(AUTHFILES))","")
	@echo Authentication files missing. Make sure to run from
	@echo directory where challenge was extracted.
	exit 1
else
	zip $@ $^ $(HIDDENFILES) $(HIDDENEXTRAS) $(AUTHFILES)
endif
