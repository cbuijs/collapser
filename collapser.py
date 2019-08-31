#!/usr/bin/env python2
# -*- coding: utf-8 -*-
'''
=========================================================================================
 dns-filter.py: v0.55-20190118 Copyright (C) 2019 Chris Buijs <cbuijs@chrisbuijs.com>
=========================================================================================

 DNS filtering extension for the unbound DNS resolver.

=========================================================================================
'''
# Standard/Included modules
import sys, os, os.path, time
sys.path.append("/usr/local/lib/python2.7/dist-packages/")

##########################################################################################

def get_data(rdtype, answer):
    if rdtype == 'A':
        rdata = "%d.%d.%d.%d"%(ord(answer[2]),ord(answer[3]),ord(answer[4]),ord(answer[5]))
    elif rdtype == 'AAAA':
        rdata = "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"%(ord(answer[2]),ord(answer[3]),ord(answer[4]),ord(answer[5]),ord(answer[6]),ord(answer[7]),ord(answer[8]),ord(answer[9]),ord(answer[10]),ord(answer[11]),ord(answer[12]),ord(answer[13]),ord(answer[14]),ord(answer[15]),ord(answer[16]),ord(answer[17]))
    elif rdtype in ('CNAME', 'NS'):
        rdata = decode_data(answer,0)
    elif rdtype == 'MX':
        rdata = decode_data(answer,1)
    elif rdtype == 'PTR':
        rdata = decode_data(answer,0)
    elif rdtype == 'SOA':
        rdata = decode_data(answer,0).split(' ')[0][0]
    elif rdtype == 'SRV':
        rdata = decode_data(answer,5)
    else:
        rdata = False

    return rdata


# Decode names/strings from response message
def decode_data(rawdata, start):
    text = ''
    remain = ord(rawdata[2])
    for c in rawdata[3 + start:]:
       if remain == 0:
           text += '.'
           remain = ord(c)
           continue
       remain -= 1
       text += c
    return text.lower()


##########################################################################################
# UNBOUND DEFS START
##########################################################################################

# Initialization
def init(id, cfg):
    log_info('COLLAPSER: Initializing ...')

    return True

# Unload/Finish-up
def deinit(id):
    log_info('COLLAPSER: Shutting down ...')
    log_info('COLLAPSER: DONE!')
    return True

# Inform_Super
def inform_super(id, qstate, superqstate, qdata):
    return True

# Main beef/process
def operate(id, event, qstate, qdata):
    # New query or new query passed by other module
    if event == MODULE_EVENT_NEW or event == MODULE_EVENT_PASS:
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    elif event == MODULE_EVENT_MODDONE:
        msg = qstate.return_msg
        if msg:
            rep = msg.rep
            repttl = rep.ttl
            rc = rep.flags & 0xf
            if (rc == RCODE_NOERROR) and (rep.an_numrrsets > 0):
                rrs = list()
                qname = False
                for rrset in range(0, rep.an_numrrsets):
                    rk = rep.rrsets[rrset].rk
                    rdtype = rk.type_str.upper()
                    rdname = rk.dname_str.lower()
                    if not qname:
                        if rdtype != 'CNAME':
                            qstate.ext_state[id] = MODULE_FINISHED
                            return True

                        qname = rdname

                    data = rep.rrsets[rrset].entry.data

                    # Equalize TTLS
                    if config['equalizettl']:
                        for rr in range(0, data.count):
                            data.rr_ttl[rr] = repttl

                    # Check data
                    for rr in range(0, data.count):
                        answer = data.rr_data[rr]
                        rdata = get_data(rdtype, answer)
                        rrs.append((rdname, repttl, rdtype, rdata))

                firstname = rrs[0][0]

                if rrs[-1][2] == 'A':
                    rmsg = DNSMessage(firstname, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA )
                else:
                    rmsg = DNSMessage(firstname, RR_TYPE_AAAA, RR_CLASS_IN, PKT_QR | PKT_RA )

                count = 0
                for rr in rrs:
                    if rr[2] == rrs[-1][2]:
                        count += 1
                        rmsg.answer.append('{0} {1} IN {2} {3}'.format(firstname, repttl, rr[2], rr[3]))

                rmsg.set_return_msg(qstate)
                if not rmsg.set_return_msg(qstate):
                    log_err('COLLAPSER ERROR: ' + str(rmsg.answer))
                    qstate.ext_state[id] = MODULE_ERROR
                    return True

                log_info('COLLAPSER: {0}/{1} went from {2} to {3} ({4}) RRs'.format(firstname, rrs[0][2], len(rrs), count, rrs[-1][2]))
                # Cache new answer
                invalidateQueryInCache(qstate, qstate.return_msg.qinfo)
                qstate.no_cache_store = 0
                qstate.return_msg.rep.security = 2
                storeQueryInCache(qstate, qstate.return_msg.qinfo, qstate.return_msg.rep, 0)

            else:
                qstate.return_rcode = rc

            # Done
            qstate.ext_state[id] = MODULE_FINISHED
            return True

        else:
            log_err('COLLAPSER: NO RESPONSE MESSAGE')
            qstate.ext_state[id] = MODULE_ERROR
            return True

    # Oops, non-supported event
    log_info('BAD Event {0}'.format(event), True)
    qstate.ext_state[id] = MODULE_ERROR

    return False

# <EOF>
