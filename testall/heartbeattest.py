import os
import subprocess

data='./Datasets'
broscripts='./heartbeatscripts'


datasets=os.listdir(data)
scripts=os.listdir(broscripts)

#subprocess.call(["ls","-l"])

for dataset in datasets :
	name=dataset
	name=name.split('.')[0] + "_logs"
	path="./heartbeatlogs/"+name
	os.mkdir(path)
	path=path+"/"
	for script in scripts: 
		if(script !="packettrack.bro"):
			subprocess.call(["bro","-r","./Datasets/"+dataset,"./heartbeatscripts/"+script])
	logs=os.listdir('.')
	for log in logs:
		temp=log.split('.')
		if len(temp)>1 and temp[1]=="log":
			subprocess.call(["mv","./"+log, path])
	print ("finished set")
	print("##################")
