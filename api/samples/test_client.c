#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include <string.h>

#define BUF_LENGTH 50
#define LIBC "libc"

enum ACCESS_TYPE {
    INS_EXEC,
    MEMORY_READ
};

struct forbid_func {
    generic_func_t base;
    char name[256];
    int found;
};

module_data_t *libc;
FILE *f = NULL;
bool bb_in_app = false;
app_pc app_base, app_end;
struct forbid_func *fns = NULL;
int fns_cur = 0;
int count = 0;

bool check_forbidden_functions(app_pc addr, bool mem)
{
    for (int i = 0; i < fns_cur; i++) {
        if (fns[i].base && addr == (app_pc)fns[i].base) {
            fns[i].found |= mem ? (1 << MEMORY_READ) : (1 << INS_EXEC);
            return true;
        }
    }
    return false;
}

void clean_call(app_pc addr)
{
    /*
     * Here, we have a problem. The address loaded might be equivalent to
     * something like this in C :
     * void *addr = &strcmp
     * Here, we are not putting the address of strcmp in `addr`, but the
     * address of the entry in the plt.
     * To be sure, we are getting all the tricks, we thus need to check
     * the value of `addr` and `*addr`.
     * So here, `addr` might correspond to the plt address (or the address itself),
     * and `rel_addr` might correspond to the address itself, or the first
     * instructions of the function.
     */
    app_pc rel_addr = *(app_pc *)addr;
    if (check_forbidden_functions(addr, true)
        || check_forbidden_functions(rel_addr, true))
        return;
}

dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb,
        instr_t *instr, bool for_trace,
        bool translating, void *user_data)
{
    if (bb_in_app)
        check_forbidden_functions(dr_fragment_app_pc(tag), false);

    if (dr_fragment_app_pc(tag) >= app_base &&
            dr_fragment_app_pc(tag) < app_end)
        bb_in_app = true;
    else
        bb_in_app = false;


    if (!bb_in_app || !instr_reads_memory(instr))
        return DR_EMIT_DEFAULT;

    reg_id_t reg_ptr, reg_tmp;
    for (int i = 0; i < instr_num_srcs(instr); i++) {
        if (opnd_is_memory_reference(instr_get_src(instr, i))) {

            /* Dirty. One might want to store the access with the tls API part
             * and flush it at the beginning of the next fragment.
             */
            drreg_reserve_register(drcontext, bb, instr, NULL, &reg_tmp);
            drreg_reserve_register(drcontext, bb, instr, NULL, &reg_ptr);
            drutil_insert_get_mem_addr(drcontext, bb, instr,
                                       instr_get_src(instr, i),
                                       reg_ptr, reg_tmp);
            dr_insert_clean_call(drcontext, bb, instr, (void *)clean_call,
                                 false, 1, opnd_create_reg(reg_ptr));
            drreg_unreserve_register(drcontext, bb, instr, reg_ptr);
            drreg_unreserve_register(drcontext, bb, instr, reg_tmp);
        }
    }

    return DR_EMIT_DEFAULT;
}

static void
event_exit(void)
{
    for (int i = 0; i < fns_cur; i++) {
        if (!fns[i].found)
            continue;
        /*
         * An instruction execution always implies there has been a read before.
         * For more reliable output, we are doing this weird check !
         */
        if (fns[i].found & (1 << MEMORY_READ) &&
            !(fns[i].found & (1 << INS_EXEC)))
            dr_printf("%s function address is read\n", fns[i].name);
        if (fns[i].found & (1 << INS_EXEC))
            dr_printf("%s function is called\n", fns[i].name);
    }
    dr_global_free(fns, count * sizeof(*fns));
}

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    if (strncmp(dr_module_preferred_name(info), LIBC, strlen(LIBC)))
        return;

    for (int i = 0; i < fns_cur; i++) {
        generic_func_t f = dr_get_proc_address(info->handle, fns[i].name);

        //For the moment, we panic if we can't find the function in the libc
        DR_ASSERT(f);

        fns[i].base = f;
        dr_printf("lib : %s - %s addr : %p\n",
                  dr_module_preferred_name(info), fns[i].name, fns[i].base);
    }
}

static void
event_module_unload(void *drcontext, const module_data_t *info)
{
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    if (argc < 2)
        return;

    f = fopen(argv[1], "r");
    char line[256];
    while (fgets(line, sizeof(line), f)) {
      count++;
    }
    fns = dr_global_alloc(count * sizeof(*fns));
    fseek(f, 0, SEEK_SET);
    while (fgets(line, sizeof(line), f)) {
        strncpy(fns[fns_cur].name, line, strlen(line) - 1);
        fns[fns_cur].found = 0;
        fns[fns_cur].base = NULL;
        fns_cur++;
    }

    fclose(f);

    app_base = dr_get_main_module()->start;
    app_end = dr_get_main_module()->end;

    drreg_options_t ops = {sizeof(ops), 4 /*max slots needed*/, false};

    if (!drmgr_init() || !drutil_init() || drreg_init(&ops) != DRREG_SUCCESS)
        return;

    dr_register_exit_event(event_exit);
    drmgr_register_module_load_event(event_module_load);
    drmgr_register_module_unload_event(event_module_unload);
    drmgr_register_bb_instrumentation_event(NULL /*analysis_func*/,
                                            event_app_instruction,
                                            NULL);
}
