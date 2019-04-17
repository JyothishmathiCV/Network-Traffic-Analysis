import os
import subprocess
import sys

data='./Datasets'
broscripts='./Scripts'
genlogs="./logs"

#arguments=sys.argv[1:]
data=sys.argv[1]
broscripts=sys.argv[2]
genlogs=sys.argv[3]

datasets=os.listdir(data)
scripts=os.listdir(broscripts)

nofdata=len(data)
i=1

#subprocess.call(["ls","-l"])

for dataset in datasets :
	name=dataset
	name=name.split('.')[0] + "_logs"
	path=genlogs+"/"+name
	os.mkdir(path)
	path=path+"/"
	for script in scripts: 
		subprocess.call(["bro","-r",data+"/"+dataset,broscripts+"/"+script])
	logs=os.listdir('.')
	for log in logs:
		temp=log.split('.')
		if len(temp)>1 and temp[1]=="log":
			subprocess.call(["mv","./"+log, path])
	print ("Finished set " )
	print ("Completed " + str(i) + " datasets out of " + str(nofdata))
        print ("######################################")
	i=i+1
