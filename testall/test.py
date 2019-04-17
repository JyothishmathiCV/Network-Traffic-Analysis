import os
import subprocess

data='./Datasets'
broscripts='./Scripts'


datasets=os.listdir(data)
scripts=os.listdir(broscripts)

i=0
#subprocess.call(["ls","-l"])

for dataset in datasets :
	name=dataset
        i+=1
	name=name.split('.')[0] + "_logs"
	path="./logs/"+name
	os.mkdir(path)
	path=path+"/"
	for script in scripts: 
		subprocess.call(["bro","-r","./Datasets/"+dataset,"./Scripts/"+script])
	logs=os.listdir('.')
	for log in logs:
		temp=log.split('.')
		if len(temp)>1 and temp[1]=="log":
			subprocess.call(["mv","./"+log, path])
        print ("Finished set " )
        print ("######################################")
        
        
