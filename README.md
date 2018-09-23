#DO NOT USE YET - STILL UNDER DEVELOPMENT
#For Alt UI on openLuup ONLY -- Do not install on Vera


# GCal3
A plugin for use with vera and openLuup home automation.

This version of Google Calendar supports the Google V3 API's and the necessary authentication required by Google.

##Google Credentials
In Google API's prior to V3 it was possible to access a calendar using a url that included a unique key.
Now you need explicit credentials (service account) as well as an ID that identifies the calendar you wish to access.
You will also need to share the calendar with your service account.
The document '[i]Setting up a Google V3 API Service Account[/i]' gives step-by-step instructions on how to create an account, get a credentials file and your Calendar ID.

**You need to set up credentials before you use GCAL3**

##Installation and Users Guide**
Be sure to read the [i]Installation and User Guide[/i].
There are a lot of features and the guide will help.  If the guide is in error, misleading or ambiguous
I'll try to fix that too.

##Debugging##
GCal3 has three levels of debug messages (1-3).   For troubleshooting, set gc_debug to 3.
Each plugin has the ability to capture it's own log files or you can use the features in Alt UI

To assist folks with initial setup / troubleshooting / proving that the plugin is working -- I have created a test calendar and a test set of credentials.  These are setup as part of the initial install.

If you need to retest with the test files use thefollowing steps (in this order).
1. Get a copy of the 2 files: GCal3TestCalendar.txt and GCal3Test.json from here


2. Switch the GCal plugin to Bypass Mode and leave it there until all the steps below are complete.
3. Change the Credential File field to GCal3Test.json into the and Press "Set".
4.  In the Control tab (of the plugin).  Copy the contents of the GCal3TestCalendar.txt file into the Calendar ID field and press "Set".
5.  Upload the GCal3Test.json file to /.....
6. Switch the GCal plugin to Arm Mode

You will then see the next event show up.  Note that these events are named for the time (in GMT) that they occur -- so the actual time, in your timezone may be different.

**Be sure to replace the test values for CalendarID and Credential File with your own afterwards ( Following the sequence above).**

##Release Method##
Most releases will be through the mios marketplace and the openLuup App Store.
