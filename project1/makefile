all: sucms_list sucms_delete

sucms_list: sucms_list.cpp SUCMS.h
	g++ sucms_list.cpp -o sucms_list -lcrypto -lssl

sucms_delete: sucms_delete.cpp SUCMS.h
	g++ sucms_delete.cpp -o sucms_delete -lcrypto -lssl
