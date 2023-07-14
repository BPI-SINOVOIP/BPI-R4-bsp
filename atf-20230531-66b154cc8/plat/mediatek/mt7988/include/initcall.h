#ifndef INITCALL_H
#define INITCALL_H

typedef int (*init_fnc_t)(int data);

struct initcall_entry {
	const char *name;
	const init_fnc_t func;
	const int data;
};

int initcall_run_list(void);

#endif /* INITCALL_H */
