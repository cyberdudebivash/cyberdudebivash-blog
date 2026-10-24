'use strict';
jest.mock('../runtime-env',()=>({isCloudflareWorkers:jest.fn(()=>true)}));
const {isCloudflareWorkers}=require('../runtime-env');
const d1=require('../d1');

beforeEach(()=>{
  d1.setD1Binding(null);
  isCloudflareWorkers.mockReturnValue(true);
  global.fetch=jest.fn(async()=>{throw Error('REST must never run from Worker');});
});
afterEach(()=>{d1.setD1Binding(null);jest.restoreAllMocks();});

test('missing native D1 in Worker fails closed before any REST HTTP or billed external call',async()=>{
  expect(d1.hasNativeBinding()).toBe(false);
  expect(d1.isConfigured()).toBe(false);
  await expect(d1.query('SELECT 1')).rejects.toThrow('D1 native binding required in Worker');
  await expect(d1.run('DELETE FROM alerts')).rejects.toThrow('D1 native binding required in Worker');
  expect(global.fetch).not.toHaveBeenCalled();
});

test('native binding remains operational, then explicit null makes next read fail closed',async()=>{
  const prepare=jest.fn(()=>({
    bind:jest.fn().mockReturnThis(),
    run:jest.fn(async()=>({results:[{n:7}],success:true,meta:{}}))
  }));
  d1.setD1Binding({prepare});
  expect(d1.hasNativeBinding()).toBe(true);
  expect(await d1.query('SELECT 7 AS n')).toEqual([{n:7}]);
  expect(prepare).toHaveBeenCalledWith('SELECT 7 AS n');
  d1.setD1Binding(null);
  expect(d1.hasNativeBinding()).toBe(false);
  await expect(d1.query('SELECT 7 AS n')).rejects.toThrow('D1 native binding required in Worker');
  expect(global.fetch).not.toHaveBeenCalled();
});
