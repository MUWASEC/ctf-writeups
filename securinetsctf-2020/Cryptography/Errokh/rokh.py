import numpy as np 

def messig_up(message,key):
	parts=""
	while len(message)!=0:
		to_work_with=message[:9]
		first_one=np.zeros((3,3))
		k=0
		for i in range(3):
			for j in range(3):
				first_one[i][j]=ord(to_work_with[k])
				k+=1
		finish=np.transpose(np.matmul(first_one,key))
		for i in range(3):
			for j in range(3):
				parts=parts + str(finish[i,j])+ " "
		parts+="----"
		message=message[9:]
	return parts



flag="TODO"
key=np.matrix("1 2 3;0 1 4;5 6 0")
cipher=messig_up(flag,key)
print cipher

'''
Ciphertext : 578.0 642.0 690.0 861.0 978.0 1017.0 653.0 807.0 734.0 ----710.0 579.0 360.0 1067.0 826.0 576.0 837.0 504.0 553.0 ----425.0 363.0 583.0 685.0 625.0 892.0 680.0 736.0 750.0 ----670.0 585.0 612.0 985.0 874.0 893.0 705.0 666.0 620.0 ----697.0 423.0 688.0 1028.0 657.0 939.0 744.0 576.0 441.0
'''