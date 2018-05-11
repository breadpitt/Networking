all: sucms_list sucms_delete sucms_read

sucms_list: sucms_list.cpp SUCMS.h
	g++ sucms_list.cpp -o sucms_list -lcrypto -lssl

sucms_delete: sucms_delete.cpp SUCMS.h
	g++ sucms_delete.cpp -o sucms_delete -lcrypto -lssl

sucms_read: sucms_read.cpp SUCMS.h
	g++ sucms_read.cpp -o sucms_read -lcrypto -lssl