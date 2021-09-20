#!/usr/bin/env python
# -*- coding: utf-8 -*-

import multiprocessing

def f(name):
    print ('hello0¡')

if __name__ == '__main__':
    pool = multiprocessing.Pool() #use all available cores, otherwise specify the number you want as an argument
    for i in range(0, 512):
        pool.apply_async(f, args=(i,))
    pool.close()
    pool.join()
