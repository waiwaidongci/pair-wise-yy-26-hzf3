import os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import DomainError, VulnerabilityDB

class VulnerabilityFlowTest(unittest.TestCase):
    def setUp(self):
        fd,self.path=tempfile.mkstemp(suffix=".db"); os.close(fd); self.db=VulnerabilityDB(self.path)
        self.reporter=self.db.add_user("报告人","reporter","研究所"); self.coord=self.db.add_user("协调员","coordinator","响应中心"); self.maint=self.db.add_user("维护者","maintainer","项目组"); self.outsider=self.db.add_user("旁观者","reporter","外部")
        self.product=self.db.add_product("网关","项目组")
        self.report=self.db.create_report("鉴权绕过",self.product,self.reporter,"特制请求可绕过鉴权","2026-10-30",["3.2.0"])
    def tearDown(self): self.db.close(); os.unlink(self.path)
    def _advance_to_resolved(self):
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.set_status(self.report,"triaged",self.coord)
        self.db.set_status(self.report,"fixing",self.coord)
        self.db.set_fix_plan(self.report,self.maint,"增加鉴权前置校验", "2026-10-20")
        self.db.set_status(self.report,"resolved",self.coord)
        self.db.create_advisory_draft(self.report,"受影响版本 3.2.0。请升级到 3.2.1。",self.coord)
    def _start_review(self, assignees=None):
        return self.db.start_review_round(self.report,self.coord,assignees or [self.reporter,self.maint],"披露前复核")
    def _approve_round(self, round_id):
        self.db.cast_review_vote(round_id,self.reporter,"approve")
        self.db.cast_review_vote(round_id,self.maint,"approve")
    def test_full_disclosure_flow_and_early_publish_rejected(self):
        self._advance_to_resolved()
        with self.assertRaisesRegex(DomainError,"提前披露"):
            self.db.publish_report(self.report,self.coord,"2026-10-01")
        round_id=self._start_review()
        with self.assertRaisesRegex(DomainError,"未表态"):
            self.db.publish_report(self.report,self.coord,"2026-10-30")
        self._approve_round(round_id)
        self.db.publish_report(self.report,self.coord,"2026-10-30")
        advisory=self.db.get_advisory(self.report,self.outsider)
        self.assertEqual("published",advisory["status"])
        self.assertTrue(self.db.notifications_for(self.maint))
    def test_denies_outsider_and_duplicate_report(self):
        with self.assertRaisesRegex(DomainError,"无权"):
            self.db.get_report_for_user(self.report,self.outsider)
        with self.assertRaisesRegex(DomainError,"重复"):
            self.db.create_report("重复问题",self.product,self.reporter,"相同版本的另一份报告","2026-11-01",["3.2.0"])
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.add_evidence(self.report,"协调材料","secret","coordinator",self.coord)
        visible=self.db.get_report_for_user(self.report,self.maint)
        self.assertEqual([],visible["evidence"])
    def test_objection_blocks_publish_until_new_round_approves(self):
        self._advance_to_resolved()
        round_id=self._start_review()
        with self.assertRaisesRegex(DomainError,"反对意见至少"):
            self.db.cast_review_vote(round_id,self.maint,"object","")
        self.db.cast_review_vote(round_id,self.reporter,"approve")
        self.db.cast_review_vote(round_id,self.maint,"object","升级指南缺失，影响范围不明")
        with self.assertRaisesRegex(DomainError,"反对意见"):
            self.db.publish_report(self.report,self.coord,"2026-10-30")
        round2=self._start_review()
        with self.assertRaisesRegex(DomainError,"取代"):
            self.db.cast_review_vote(round_id,self.reporter,"approve","旧批次补票")
        self._approve_round(round2)
        self.db.publish_report(self.report,self.coord,"2026-10-30")
        self.assertEqual("published",self.db.get_advisory(self.report,self.outsider)["status"])
        with self.assertRaisesRegex(DomainError,"不能更正版本"):
            self.db.correct_versions(self.report,self.coord,["4.0"],[],"披露后尝试更正")
    def test_review_round_rules_and_pending_voters(self):
        self._advance_to_resolved()
        with self.assertRaisesRegex(DomainError,"只有协调员"):
            self.db.start_review_round(self.report,self.maint,[self.reporter],"非协调员发起")
        with self.assertRaisesRegex(DomainError,"协作范围"):
            self.db.start_review_round(self.report,self.coord,[self.outsider],"包含外部用户")
        with self.assertRaisesRegex(DomainError,"至少一名"):
            self.db.start_review_round(self.report,self.coord,[],"没有评审人")
        with self.assertRaisesRegex(DomainError,"发布接口"):
            self.db.set_status(self.report,"published",self.coord)
        round_id=self._start_review()
        with self.assertRaisesRegex(DomainError,"指定的评审人"):
            self.db.cast_review_vote(round_id,self.coord,"approve")
        self.db.cast_review_vote(round_id,self.reporter,"approve","确认影响范围")
        view=self.db.get_report_for_user(self.report,self.coord)
        latest=view["reviews"][-1]
        self.assertEqual("open",latest["status"])
        self.assertEqual(["维护者"],[p["name"] for p in latest["pending"]])
        with self.assertRaisesRegex(DomainError,"维护者"):
            self.db.publish_report(self.report,self.coord,"2026-10-30")
    def test_version_corrections_are_logged_and_reset_review(self):
        self._advance_to_resolved()
        round_id=self._start_review()
        self._approve_round(round_id)
        self.db.correct_versions(self.report,self.maint,["3.1.8"],[],"确认 3.1.8 也受影响")
        view=self.db.get_report_for_user(self.report,self.coord)
        self.assertEqual(["3.2.0","3.1.8"],[v["version_key"] for v in view["versions"]])
        corrections=view["version_corrections"]
        self.assertEqual(1,len(corrections))
        self.assertEqual("add",corrections[0]["action"])
        self.assertEqual("3.1.8",corrections[0]["version_key"])
        self.assertEqual("确认 3.1.8 也受影响",corrections[0]["reason"])
        self.assertEqual("维护者",corrections[0]["changed_by_name"])
        self.assertEqual("superseded",view["reviews"][0]["status"])
        with self.assertRaisesRegex(DomainError,"评审"):
            self.db.publish_report(self.report,self.coord,"2026-10-30")
        self.db.correct_versions(self.report,self.coord,[],["3.1.8"],"复测后排除 3.1.8")
        view=self.db.get_report_for_user(self.report,self.coord)
        self.assertEqual(["3.2.0"],[v["version_key"] for v in view["versions"]])
        self.assertEqual(["add","remove"],[c["action"] for c in view["version_corrections"]])
        with self.assertRaisesRegex(DomainError,"至少5个字符"):
            self.db.correct_versions(self.report,self.maint,["3.1.9"],[],"短")
        with self.assertRaisesRegex(DomainError,"已在受影响列表"):
            self.db.correct_versions(self.report,self.maint,["3.2.0"],[],"重复添加测试")
        with self.assertRaisesRegex(DomainError,"不在受影响列表"):
            self.db.correct_versions(self.report,self.maint,[],["9.9.9"],"移除不存在版本")
        with self.assertRaisesRegex(DomainError,"至少保留一个"):
            self.db.correct_versions(self.report,self.maint,[],["3.2.0"],"全部移除测试")
        with self.assertRaisesRegex(DomainError,"无权"):
            self.db.correct_versions(self.report,self.outsider,["9.9.9"],[],"外部用户尝试")

if __name__=="__main__": unittest.main()
