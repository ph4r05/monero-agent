# Log processor, extracts timings and memory consumption stats
#
#

import argparse
import logging
import re
import json
import collections

import coloredlogs

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.INFO, use_chroot=False)

# Data collected by calling diag() on a real device - benchmarking
perfs = [
    {'random_scalar': 0.211 / 512.},
    {'encodeint_into': 4.5150 / 131072.},
    {'encodeint': 4.5150 / 131072.},
    {'decodeint_into': 7.3500 / 131072.},
    {'decodeint': 7.3500 / 131072.},
    {'decodeint_into_noreduce': 4.6370 / 131072.},
    {'sc_copy': 3.2540 / 131072.},

    {'scalarmult_base': 2.0880 / 256.},
    {'encodepoint_into': 144.4460 / 131072.},
    {'decodepoint_into': 154.7630 / 131072.},

    {'scalarmult_into': 370.1170 / 16384.},
    {'scalarmult_base_into': 127.0400 / 16384.},
    {'point_add_into': 2.0050 / 16384.},
    {'point_sub_into': 2.0730 / 16384.},
    {'add_keys2_into': 309.2620 / 16384.},
    {'add_keys3_into': 336.4210 / 16384.},
    {'check_ed25519point': 134.7630 / 131072.},

    {'sc_mul_into': 6.4250 / 131072.},
    {'sc_muladd_into': 7.1800 / 131072.},
    {'sc_mulsub_into': 7.2060 / 131072.},
    {'sc_sub_into': 4.1880 / 131072.},
    {'sc_add_into': 4.1880 / 131072.},
    {'sc_inv_into': 106.3400 / 131072.},

    {'_vector_exponent_custom': 3.192 / 128.},
    {'_hadamard_fold': 1.646 / 128.},
    {'_scalar_fold': 0.133 / 128.},

    {'new_point': 0.0440 / 256.},
    {'new_scalar': 0.0910 / 256.},
    {'keccak_hash_into': 63.7650 / 131072.},
    {'xmr_fast_hash': 63.7650 / 131072.},
    {'cn_fast_hash': 63.7650 / 131072.},
    {'hash_to_point_into': 398.0110 / 131072.},
    {'hash_to_scalar_into': 70.6690 / 131072.},
    {'gen_commitment': 309.2620 / 16384.},
]


TICKS_PER_SECOND = 1000000.0
MAX_TICKS = 1073741824  # 2**30


def tic2sec(tic):
    return tic / TICKS_PER_SECOND


def avg(iterable):
    return sum(iterable) / float(len(iterable))


def perfs_map(prefs):
    res = collections.OrderedDict()
    for e in prefs:
        for k in e:
            res[k] = e[k]
    return res


def jsonfix(line):
    if ': False' in line:  # fixing json probs
        line = line.replace(': False', ': false')
    if ': True' in line:  # fixing json probs
        line = line.replace(': True', ': true')
    return line


def reclist2dict(data):
    if data is None:
        return None
    res2 = collections.OrderedDict()
    res = collections.defaultdict(lambda: 0)
    for rec in data:
        for k in rec:
            res[k] += rec[k]
            res2[k] = res[k]
    return res2


class MemReader(object):
    def __init__(self, data):
        self.data = data
        self.cline = -1
        self.ctext = ""
        self.mfree = 0
        self.malloc = 0
        self.last_time = None

        self.last_counters = None
        self.in_ctrs = False
        self.ctrs_cnt = 0
        self.ctrs_acc = []

        self.last_mem = []
        self.in_mem = False
        self.mem_acc = []
        self.mem_cnt = 0

        self.last_dumps = []
        self.last_writes = []

    def full_line(self):
        return self.data[self.cline]

    def next_section(self):
        offset = 0
        res = self.next_entry()
        if res is None:
            return None
        while not res[1]:
            offset += 1
            res = self.next_entry()
            if res is None:
                return None
        return res[0], res[1], offset

    def next(self, to_section=False):
        if to_section:
            return self.next_section()
        else:
            return self.next_entry()

    def has_data(self):
        return self.cline + 1 < len(self.data)

    def next_entry(self):
        for i in range(self.cline + 1, len(self.data)):
            self.cline = i
            line = self.data[i]

            r1 = r"^.*F:\s*(\d+).*A:\s*(\d+).*"
            r2 = r"^.*====.*Free:\s*(\d+).*Allocated:\s*(\d+).*"
            is_entry = True

            ma = re.match(r1, line)
            if ma is None:
                ma = re.match(r2, line)

            if ma is None:
                is_entry = False

            if is_entry:
                self.in_ctrs = False
                self.ctext = line
                self.mfree = int(ma.group(1))
                self.malloc = int(ma.group(2))
                self.last_time = int(line.split(" ", 2)[0])
                is_section = "####" in line or "====" in line
                return self.mfree, self.malloc, is_section

            # Ops report
            if 'Fnc call report' in line:
                self.in_ctrs = True
                self.ctrs_cnt += 1
                self.ctrs_acc = []
                continue

            if self.in_ctrs and ']' in line:
                self.in_ctrs = False
                acc = [x.strip() for x in self.ctrs_acc]
                if len(acc) > 0:
                    acc[-1] = acc[-1].rstrip(',')
                jsstr = '[%s]' % ''.join(acc)
                self.last_counters = json.loads(jsstr)

            elif self.in_ctrs:
                self.ctrs_acc.append(line)

            # Size report
            if 'SizeReport:' in line:
                self.in_mem = True
                self.mem_cnt += 1
                self.mem_acc = [jsonfix(line.split(':', 1)[1])]
                continue

            if self.in_mem and ']}' in line:
                self.in_mem = False
                acc = [x.strip() for x in self.mem_acc]
                if len(acc) > 0:
                    acc[-1] = acc[-1].rstrip(',')
                jsstr = ''.join(acc) + ']}'
                self.last_mem.append(json.loads(jsstr))

            elif self.in_mem:
                line = line.strip()
                if line.startswith('"'):  # fixing json probs
                    line = '{%s},' % line.rstrip(',')
                self.mem_acc.append(jsonfix(line))

            if '!!!!!Dump finished:' in line:
                pts = line.split(':')
                self.last_dumps.append((int(pts[1]), int(pts[3])))

            if ' write: <' in line:
                self.last_writes.append(int(line.split(" ", 2)[0]))

        return None, None, None

    def get_ops(self):
        if self.last_counters is None:
            return None
        r = self.last_counters
        self.last_counters = None
        return r

    def get_size(self):
        r = self.last_mem
        self.last_mem = []
        return r

    def get_dumps(self):
        r = self.last_dumps
        self.last_dumps = []
        return r

    def get_writes(self):
        r = self.last_writes
        self.last_writes = []
        return r


class MemAnalyze(object):
    def __init__(self):
        self.args = None

    def read_files(self, files):
        file_data = []

        for idx, file in enumerate(files):
            with open(file) as fh:
                file_data.append(fh.readlines())

        if len(file_data) != 1:
            raise ValueError("Exactly 1 file is required")

        if self.args.tx:
            self.analyze_tx(file_data)
        else:
            self.analyze_bp(file_data)

    def analyze_tx(self, file_data):
        ops_metrics = perfs_map(perfs)
        cops_sum = collections.defaultdict(lambda: 0)
        ma = MemReader(file_data[0])

        # Multiple experiments per one read, safe limit, terminate eventually
        jsres_total = []
        jsres = collections.OrderedDict()
        jsres_total.append(jsres)

        for cround in range(self.args.max_rec if self.args.max_rec else 100):
            if not ma.has_data():
                break

            logger.info('### Experiment: %s' % cround)
            process_exp = True
            mem_base = 0
            jsres['exp'] = cround

            first_step_time = 0
            last_step_time = 0
            cur_step_mems = []

            jsrnd = None
            jsres['steps'] = []

            while process_exp:
                ar = ma.next()
                mfree, malloc = ar[0], ar[1]
                if mfree is None:
                    break

                step = None
                if ', step:' in ma.ctext:
                    m = re.match(r'.*,\s*step:\s*(-?[\d]+)\s*.*', ma.ctext)
                    if m:
                        step = int(m.group(1))

                aops = ma.get_ops()
                amem = ma.get_size()
                adump = ma.get_dumps()  # [(ideal, real)] state size
                awrites = ma.get_writes()

                # print(ar, step, ma.ctext, aops, amem, adump)
                # print(ar, step, ma.ctext, None, None, adump, awrites)
                logger.info('ar: %s, step: %s, line: %s' % (ar, step, ma.ctext.strip()))

                is_tx_start = step == 1
                in_tx_end = step == -1
                in_step = step is None

                if not in_step:
                    ctime = ma.last_time

                    # Finalize current step data, time, mems, ...
                    if jsrnd and last_step_time is not None:
                        jsrnd['time'] = ctime - last_step_time
                        jsrnd['rtime'] = (awrites[0] - last_step_time) if awrites else None
                        jsrnd['mems'] = cur_step_mems
                        jsrnd['state'] = adump[0] if adump else None
                        jsrnd['ops'] = reclist2dict(aops)

                    jsrnd = collections.OrderedDict()
                    jsrnd['step'] = step
                    jsres['steps'].append(jsrnd)

                    cur_step_mems = [malloc] if not is_tx_start else []
                    last_step_time = ctime

                else:
                    cur_step_mems.append(malloc)

                if is_tx_start:
                    mem_base = malloc
                    first_step_time = ma.last_time
                    jsres['mem_base'] = mem_base
                    jsres['time_base'] = first_step_time

                if in_tx_end:
                    process_exp = False
                    jsres['time_total'] = ma.last_time - first_step_time
                    jsres['mem_max'] = max(max(x['mems']) for x in jsres['steps'] if 'mems' in x)
                    jsres['mem_min'] = min(min(x['mems']) for x in jsres['steps'] if 'mems' in x)
                    jsres['mem_max_base'] = jsres['mem_max'] - mem_base
                    jsres['mem_max_min'] = jsres['mem_max'] - jsres['mem_min']
                    jsres['time_total_steps'] = sum(x['time'] for x in jsres['steps'] if 'time' in x)
                    jsres['rtime_total_steps'] = sum(x['rtime'] for x in jsres['steps'] if 'rtime' in x and x['rtime'] is not None)
                    jsres['max_state'] = None
                    max_state = [x['state'] for x in jsres['steps'] if 'state' in x and x['state']]

                    if max_state:
                        jsres['max_state'] = [max(x[0] for x in max_state), max(x[1] for x in max_state)]

                    acc_ops = collections.defaultdict(lambda: 0)
                    for en in jsres['steps']:
                        if 'ops' not in en or not en['ops']: continue
                        for k in en['ops']:
                            acc_ops[k] += en['ops'][k]
                    jsres['acc_ops'] = acc_ops

                    break  # terminate while

            # TODO: postprocess accumulators
            pass

            jsres = collections.OrderedDict()
            jsres_total.append(jsres)

        jsres_total.pop()
        print(json.dumps(jsres_total, indent=2))

    def analyze_bp(self, file_data):
        ops_metrics = perfs_map(perfs)
        cops_sum = collections.defaultdict(lambda: 0)
        ma = MemReader(file_data[0])

        nsteps = 0
        in_bp_sec = False

        mems_prior = []

        mcurr_steps = []
        mems_steps = [mcurr_steps]

        mcurr_ops = []
        mops_steps = [mcurr_ops]

        mtime_steps = [0]

        state_mem = []
        state_mem_real = []
        for x in file_data[0]:
            if '!!!!!Dump fin' not in x:
                continue
            pts = x.split(':')
            p = int(pts[1])
            state_mem.append(p)
            if len(pts) >= 4:
                state_mem_real.append(int(pts[3]))

        while True:
            ar = ma.next()
            mfree, malloc = ar[0], ar[1]
            if mfree is None:
                break

            is_bp_start = False
            is_bp_step = False
            if ar[2]:  # section
                is_bp_start = '+++BP START' in ma.ctext
                is_bp_step = '+++BP STEP' in ma.ctext

            if is_bp_start:
                in_bp_sec = True
                nsteps += 1
                mcurr_steps = []
                mems_steps.append(mcurr_steps)
                mcurr_ops = []
                mops_steps.append(mcurr_ops)
                mtime_steps.append(ma.last_time)

            if is_bp_step:
                in_bp_sec = False
                mtime_steps[-1] = tic2sec(ma.last_time - mtime_steps[-1])

            if nsteps == 0 and not in_bp_sec:
                mems_prior.append(malloc)  # reference sample before main sec start

            elif in_bp_sec:
                mcurr_steps.append(malloc)
                mems = ma.get_ops()
                if mems:
                    mcurr_ops.append(mems)
                    for k in mems:
                        for kk in k:
                            cops_sum[kk] += k[kk]
                    print('LMEM!', mems)

            if self.args.verbose:
                pass

        print(mems_prior)
        print(mems_steps)
        baline = mems_prior[-1]
        msteps_max = []

        print('Baseline: %s' % baline)
        maxbaline = 0
        for ix, stp in enumerate(mems_steps):
            if not stp:
                continue

            maxmem = max(stp)
            cbaline = maxmem - baline
            maxbaline = max(maxbaline, cbaline)
            cstepmax = maxmem - stp[0]
            msteps_max.append((cstepmax, ix))
            ctime = mtime_steps[ix]
            print(' .. step: %s, maxmem: %s, bline: %s, mstep: %s, tm: %s' % (ix, maxmem, cbaline, cstepmax, ctime))

        print(cops_sum)
        print(sorted(cops_sum.keys()))
        ops_sum = []
        for k in cops_sum:
            ops_sum.append({'key': k, 'ctr': cops_sum[k], 'time': cops_sum[k] * ops_metrics[k] if k in ops_metrics else None})

        print('Missing: ', sorted([x for x in cops_sum.keys() if x not in ops_metrics]))
        print('Perfs: %s' % json.dumps(ops_sum))

        print('States: %s, max state: %s' % (state_mem, max(state_mem) if state_mem else 0))
        print('StatesR: %s, max state R: %s' % (state_mem_real, max(state_mem_real) if state_mem_real else 0))
        print('Steps sorted: %s' % sorted(msteps_max))
        print('Maximal above baseline: %s' % (maxbaline, ))
        print('Mtime steps total: %.2f s = %.4f min' % (sum(mtime_steps), sum(mtime_steps)/60.))

    def main(self):
        parser = argparse.ArgumentParser(
            description="Log analysis for memory consumption"
        )
        parser.add_argument(
            "--verbose",
            dest="verbose",
            default=False,
            action="store_const",
            const=True,
            help="Append to the tee file",
        )
        parser.add_argument(
            "--tx",
            dest="tx",
            default=False,
            action="store_const",
            const=True,
            help="Transaction processing mode",
        )
        parser.add_argument(
            "--max-rec",
            dest="max_rec",
            default=None,
            type=int,
            help="Maximum records to process",
        )
        parser.add_argument(
            "files",
            metavar="FILE",
            nargs="*",
            help="files to read, if empty, stdin is used",
        )
        args = parser.parse_args()
        self.args = args

        try:
            self.read_files(args.files)

        except KeyboardInterrupt:
            logger.info("Terminating")


if __name__ == "__main__":
    anz = MemAnalyze()
    anz.main()
