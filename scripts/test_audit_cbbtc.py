import unittest
from audit_cbbtc import *
class AuditRegression(unittest.TestCase):
 def test_decimal_normalization(self):
  self.assertAlmostEqual(1/(1.0001**-67461*10**(6-8)),85044.75305727308,places=5)
 def test_hook_rules(self):
  self.assertTrue(valid_hook("0x0",3000))
  self.assertFalse(valid_hook("0x0",8388608))
  self.assertFalse(valid_hook(hex(1<<3),3000))
  self.assertTrue(valid_hook(hex((1<<3)|(1<<7)),3000))
  self.assertTrue(valid_hook(hex(1<<200),8388608))
  self.assertFalse(valid_hook(hex(1<<200),3000))
 def test_pool_keys(self):
  for pid,h,fee,ts in TARGETS:
   self.assertEqual("0x"+kh(aw(U)+aw(B)+w(fee)+w(ts)+aw(h)).hex(),pid)
 def test_slot_layout(self):
  slot=123+(0xffffff<<160)+(456<<184)+(3000<<208)
  self.assertEqual((slot>>184)&0xffffff,456)
  self.assertEqual((slot>>208)&0xffffff,3000)
 def test_abi_signed(self):
  self.assertEqual(int.from_bytes(w(-1),"big"),(1<<256)-1)
if __name__=="__main__":unittest.main()
