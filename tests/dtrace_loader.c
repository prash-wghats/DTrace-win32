#include <windows.h>
#include <stdio.h>
#include <Winbase.h>

//Advapi32.lib

#define LOAD_DEMAND 1

static int load_driver(char *filename, char *drvname, int type)
{
	char drv_loc[MAX_PATH];
	DWORD len = GetCurrentDirectory(sizeof(drv_loc), drv_loc);
	FILE *fp;
	SC_HANDLE sc_man, sc_srv;
	DWORD err;
	
	if (len = 0) 
		return 0;
	
	if (strcat(drv_loc, filename) == NULL) 
		return 0;
	
	if ((fp = fopen(drv_loc, "r")) == NULL) {
		printf("driver not found %s\n", drv_loc);
		return 0;
	}
	fclose(fp);
	
	if ((sc_man = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == NULL) {
		printf("Failed to open SC_MANAGER\n");
		return 0;
	}
		
	sc_srv = CreateService(sc_man,           // handle of service control manager database
                               drvname,             // address of name of service to start
                               drvname,             // address of display name
                               SERVICE_ALL_ACCESS,     // type of access to service
                               SERVICE_KERNEL_DRIVER,  // type of service
                               (type == LOAD_DEMAND ? SERVICE_DEMAND_START : SERVICE_SYSTEM_START),   // when to start service
                               SERVICE_ERROR_NORMAL,   // severity if service fails to start
                               drv_loc,             // address of name of binary file
                               NULL,                   // service does not belong to a group
                               NULL,                   // no tag requested
                               NULL,                   // no dependency names
                               NULL,                   // use LocalSystem account
                               NULL                    // no password for service account
                               );
	if (sc_srv == NULL && ((err = GetLastError()) != ERROR_SERVICE_EXISTS)) {
		printf("service drv %s error %d\n", drvname, err);
		return 0;
	}
	if (sc_srv == NULL) {
		sc_srv = OpenService(sc_man, drvname, SERVICE_ALL_ACCESS);
		if (sc_srv == NULL) {
			printf("Failed to open Service for %s\n", drvname);
			CloseServiceHandle(sc_man);
			return 0;
		}
	}
	if (type == LOAD_DEMAND && StartService(sc_srv, 0, NULL) == 0 ) {
		if ((err = GetLastError()) == ERROR_SERVICE_ALREADY_RUNNING) {
			CloseServiceHandle(sc_srv);
			printf("service already running %s\n", drvname);
		} else {
			printf("failed to start service drv %s error %d\n", drvname, err);
			CloseServiceHandle(sc_srv);
			CloseServiceHandle(sc_man);
			return 0;
		}
	}
	
	
	CloseServiceHandle(sc_man);	
	if (type == LOAD_DEMAND)
		printf("Loaded Driver %s\n", drvname);
	else
		printf("Service started BOOT Driver %s\n", drvname);
	return 1;
}
	
void dtrace_load_drivers(int type)
{
	if (load_driver("\\dtrace.sys", "Dtrace", type)) {
		load_driver("\\profile.sys", "Profile", type);
		load_driver("\\fasttrap.sys", "Fasttrap", type);
		load_driver("\\fbt.sys", "Fbt", type);
	}
	return;
}

static int unload_driver(char *drvname)
{
	SC_HANDLE sc_man, sc_srv;
	DWORD err;
	SERVICE_STATUS srv_st;
	
	if ((sc_man = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == NULL) {
		printf("Failed to open SC_MANAGER\n");
		return 0;
	}
	
	sc_srv = OpenService(sc_man, drvname, SERVICE_ALL_ACCESS);
	if (sc_srv == NULL) {
		printf("Failed to open Service for %s\n", drvname);
		CloseServiceHandle(sc_man);
		return 0;
	}
	
	if (ControlService(sc_srv, SERVICE_CONTROL_STOP, &srv_st) == 0) {
		printf("Failed to stop service %s\n", drvname);
	} else {
		printf("Stopped (Unloaded) driver %s\n", drvname);
	}
	
	if (DeleteService(sc_srv) == 0) {
		printf("Failed to delete service %s\n", drvname);
	} else {
		printf("deleted Service for %s\n", drvname);
	}
	
	CloseServiceHandle(sc_srv);
	CloseServiceHandle(sc_man);
	
	return 1;
}

void dtrace_unload_drivers()
{
	unload_driver("Fbt");
	unload_driver("Fasttrap");
	unload_driver("Profile");
	unload_driver("Dtrace");
}

void usage()
{
	printf("usage: load_driver -[options]\n");
	printf("	l => load drivers and start\n");
	printf("	u => stop and unload drivers\n");
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		usage();
		return 1;
	}
	
	if (argv[1][0] == '-') {
		if (argv[1][1] == 'l')
			dtrace_load_drivers(LOAD_DEMAND);
		else if (argv[1][1] == 'u') 
			dtrace_unload_drivers();
		else
			usage();
	}
	return 0;
}