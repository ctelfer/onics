#include "netvm_rt.h"

/* takes 3 arguments, returns 1 return value */
/* LOC0 = addr1, LOC1 = addr2, LOC2 = len */
struct netvm_inst nvp_memcmp[] = { 
  /*00*/{ NETVM_OC_STMEM, 4, NETVM_IF_IMMED, NETVM_LOC_2 },
  /*01*/{ NETVM_OC_STMEM, 4, NETVM_IF_IMMED, NETVM_LOC_1 },
  /*02*/{ NETVM_OC_STMEM, 4, NETVM_IF_IMMED, NETVM_LOC_0 },

  /* start of loop: if len >= 4 */
  /*03*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, NETVM_LOC_2 },
  /*04*/{ NETVM_OC_LT, 0, NETVM_IF_IMMED, 4 },
  /*05*/{ NETVM_OC_BRIF, 0, NETVM_IF_IMMED, NETVM_BRF(20) },

  /* load addr1 and subtract 4 */
  /*06*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, NETVM_LOC_0 },
  /*07*/{ NETVM_OC_DUP, 0, 0, 0 },
  /*08*/{ NETVM_OC_ADD, 0, NETVM_IF_IMMED, 4 },
  /*09*/{ NETVM_OC_STMEM, 4, NETVM_IF_IMMED, NETVM_LOC_0 },
  /*10*/{ NETVM_OC_LDMEM, 4, 0, 0 },

  /* load addr2 and subtract 4 */
  /*11*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, NETVM_LOC_1 },
  /*12*/{ NETVM_OC_DUP, 0, 0, 0 },
  /*14*/{ NETVM_OC_ADD, 0, NETVM_IF_IMMED, 4 },
  /*15*/{ NETVM_OC_STMEM, 4, NETVM_IF_IMMED, NETVM_LOC_1 },
  /*16*/{ NETVM_OC_LDMEM, 4, 0, 0 },

  /* load from addrs, compare, if not equal goto exit */
  /*17*/{ NETVM_OC_SUB, 0, 0, 0 },
  /*18*/{ NETVM_OC_DUP, 0, 0, 0 },
  /*19*/{ NETVM_OC_BRIF, 0, NETVM_IF_IMMED, NETVM_BRF(31) },
  /*20*/{ NETVM_OC_POP, 0, 0, 0 },

  /* len = len - 4, start loop again */
  /*21*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, NETVM_LOC_2 },
  /*22*/{ NETVM_OC_SUB, 0, NETVM_IF_IMMED, 4 },
  /*23*/{ NETVM_OC_STMEM, 4, NETVM_IF_IMMED, NETVM_LOC_2 },
  /*24*/{ NETVM_OC_BR, 0, NETVM_IF_IMMED, NETVM_BRB(21) },

  /* compare 2 bytes if len & 2 != 0 */
  /*25*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, NETVM_LOC_2 },
  /*26*/{ NETVM_OC_AND, 0, NETVM_IF_IMMED, 2 },
  /*27*/{ NETVM_OC_NOT, 0, 0, 0 },
  /*28*/{ NETVM_OC_BRIF, 0, NETVM_IF_IMMED, NETVM_BRF(13) },
  /*29*/{ NETVM_OC_LDMEM, 2, NETVM_IF_IMMED, NETVM_LOC_0 },
  /*30*/{ NETVM_OC_LDMEM, 2, NETVM_IF_IMMED, NETVM_LOC_1 },
  /*31*/{ NETVM_OC_SUB, 0, 0, 0 },
  /*32*/{ NETVM_OC_DUP, 0, 0, 0 },
  /*33*/{ NETVM_OC_BRIF, 0, NETVM_IF_IMMED, NETVM_BRF(17) },
  /*34*/{ NETVM_OC_POP, 0, 0, 0 },
  /*35*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, NETVM_LOC_0 },
  /*36*/{ NETVM_OC_ADD, 0, NETVM_IF_IMMED, 2 },
  /*37*/{ NETVM_OC_STMEM, 4, NETVM_IF_IMMED, NETVM_LOC_0 },
  /*38*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, NETVM_LOC_1 },
  /*39*/{ NETVM_OC_ADD, 0, NETVM_IF_IMMED, 2 },
  /*40*/{ NETVM_OC_STMEM, 4, NETVM_IF_IMMED, NETVM_LOC_1 },

  /* compare 1 byte if len & 1 != 0 */
  /*41*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, NETVM_LOC_2 },
  /*42*/{ NETVM_OC_AND, 0, NETVM_IF_IMMED, 1 },
  /*43*/{ NETVM_OC_NOT, 0, 0, 0 },
  /*44*/{ NETVM_OC_BRIF, 0, NETVM_IF_IMMED, NETVM_BRF(5) },
  /*45*/{ NETVM_OC_LDMEM, 1, NETVM_IF_IMMED, NETVM_LOC_0 },
  /*46*/{ NETVM_OC_LDMEM, 1, NETVM_IF_IMMED, NETVM_LOC_1 },
  /*47*/{ NETVM_OC_SUB, 0, 0, 0 },
  /*48*/{ NETVM_OC_BR, 0, NETVM_IF_IMMED, NETVM_BRF(2) },

  /*49*/{ NETVM_OC_PUSH, 0, 0, 0 },

  /*50*/{ NETVM_OC_RETURN, 0, NETVM_IF_IMMED, 1 },
};

int main(int argc, char *argv[])
{
  return 0;
}
