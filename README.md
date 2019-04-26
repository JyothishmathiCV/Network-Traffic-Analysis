# README #

This project generates bro logs after analysis of packet captures

###Bro Scripts###

* DNS Requests
* Periodicity

## DNS Request

* The scripts are present in the dnsscripts directory
* This code reads the packet capture and generates the logs for the DNS Failure Summary in the dnslogs directory
* The log generated has the following parameters in dnsSummary.log
	- Total no of Dns Req
	- Total no of Dns Failures
	- DNS Failure Types Detected
	- Frequency Of DNS Failed Requests
	- Total no of NXDomain Failures
	- Total no of Server Failures
	- Total no of Refused Requests
* The modified code for changed timespan of 1 min for analysing the frequency is pesent in the dns1minscripts directory

## Periodicity

* The scripts are present in the heartbeatscripts directory
* This code reads the packet capture and generates the logs for the periodicity in the heartbeatlogs directory
* The following logs are generated
	- Heartbeat.log has the following parameters
		- Total no of packets sent per connection (Src IP, Src Port, Dst IP, Dst Port)
		- Periodicity of packets sent per connection 
	- Heartbeat2.log has the following parameters
		- Total no of http requests per Dst URL
		- Periodicity of http requests sent per Dst URl
		- Dst URL
	- HeartbeatIP.log has the following parameters
		- Total no of requests sent per connection (Src IP, Src Port, Dst IP, Dst Port)
		- Periodicity of requests sent in terms of second order difference of time intervals between each request per connection 
	- HeartbeatURL.log has the following parameters
		- Total no of requests sent per Dst URL
		- Periodicity of requests sent in terms of second order difference of time intervals between each request per connection 
	- Out_log_5.log has the following parameters
		- Total no of packets sent per HTTP request per Dst URL
		- Periodicity of packets sent HTTP request per Dst URL

## File Formats Required

* The pcap files are read and related logs are generated using bro.

## Steps to Use the code

* Create a directory and store all the datasets to be analysed
* Create a directory and store all the scripts to be run on a given dataset
* Create an empty directory to store all the logs generated
* Run the python code generaltest.py with the paths to all the above directories in command line arguments as
>	 python generaltest.py ./DatasetsDirectory ./BroScriptsDirectory ./LogsDirectory
* The python code will read each dataset in the DatasetsDirectory and for each dataset it will run each bro scipt in the BroScriptsDirectory and will story the logs related to each dataset in a directory inside th LogsDirectory under the name of the dataset.