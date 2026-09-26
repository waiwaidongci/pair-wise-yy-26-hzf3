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
    def _approved_review(self):
        round_id=self.db.start_review(self.report,self.coord,[self.reporter,self.maint],"披露前复核")
        self.db.review_vote(round_id,self.reporter,"approve")
        self.db.review_vote(round_id,self.maint,"approve")
        return round_id
    def test_full_disclosure_flow_and_early_publish_rejected(self):
        self._advance_to_resolved()
        with self.assertRaisesRegex(DomainError,"提前披露"):
            self.db.publish_report(self.report,self.coord,"2026-10-01")
        self._approved_review()
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
    def test_publish_requires_completed_review(self):
        self._advance_to_resolved()
        with self.assertRaisesRegex(DomainError,"评审"):
            self.db.publish_report(self.report,self.coord,"2026-10-30")
        round_id=self.db.start_review(self.report,self.coord,[self.reporter,self.maint])
        self.db.review_vote(round_id,self.reporter,"approve")
        with self.assertRaisesRegex(DomainError,"未表态"):
            self.db.publish_report(self.report,self.coord,"2026-10-30")
        with self.assertRaisesRegex(DomainError,"已解决"):
            self.db.start_review(self.db.create_report("另一问题",self.product,self.reporter,"另一份报告","2026-10-30",["4.0.0"]),self.coord,[self.reporter])
    def test_objection_blocks_disclosure_until_withdrawn(self):
        self._advance_to_resolved()
        round_id=self.db.start_review(self.report,self.coord,[self.reporter,self.maint])
        self.db.review_vote(round_id,self.reporter,"approve")
        with self.assertRaisesRegex(DomainError,"理由"):
            self.db.review_vote(round_id,self.maint,"object")
        self.db.review_vote(round_id,self.maint,"object","影响范围被低估")
        with self.assertRaisesRegex(DomainError,"反对"):
            self.db.publish_report(self.report,self.coord,"2026-10-30")
        with self.assertRaisesRegex(DomainError,"反对"):
            self.db.set_status(self.report,"published",self.coord)
        summary=self.db.review_status(self.report)[0]
        self.assertEqual("blocked",summary["conclusion"])
        self.assertEqual([],summary["pending"])
        self.db.review_vote(round_id,self.maint,"approve","已补充影响版本")
        self.assertEqual("approved",self.db.review_status(self.report)[0]["conclusion"])
        self.db.publish_report(self.report,self.coord,"2026-10-30")
    def test_review_permissions_and_supersede(self):
        self._advance_to_resolved()
        with self.assertRaisesRegex(DomainError,"只有协调员"):
            self.db.start_review(self.report,self.maint,[self.reporter])
        with self.assertRaisesRegex(DomainError,"协作范围"):
            self.db.start_review(self.report,self.coord,[self.outsider])
        first=self.db.start_review(self.report,self.coord,[self.reporter])
        with self.assertRaisesRegex(DomainError,"指定的评审人"):
            self.db.review_vote(first,self.maint,"approve")
        second=self.db.start_review(self.report,self.coord,[self.maint])
        with self.assertRaisesRegex(DomainError,"已关闭"):
            self.db.review_vote(first,self.reporter,"approve")
        rounds=self.db.review_status(self.report)
        self.assertEqual("superseded",rounds[0]["conclusion"])
        self.assertEqual("pending",rounds[1]["conclusion"])
        self.assertEqual([self.maint],[a["user_id"] for a in rounds[1]["pending"]])
    def test_version_corrections_keep_history(self):
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        with self.assertRaisesRegex(DomainError,"原因"):
            self.db.correct_versions(self.report,self.maint,add=["3.2.1"],reason="短")
        with self.assertRaisesRegex(DomainError,"无权"):
            self.db.correct_versions(self.report,self.outsider,add=["3.2.1"],reason="外部用户尝试更正")
        self.assertEqual(1,self.db.correct_versions(self.report,self.maint,add=["3.2.1"],reason="确认 3.2.1 同样受影响"))
        self.assertEqual(1,self.db.correct_versions(self.report,self.coord,remove=["3.2.0"],reason="回读代码后排除 3.2.0"))
        visible=self.db.get_report_for_user(self.report,self.coord)
        self.assertEqual(["3.2.1"],[v["version_key"] for v in visible["versions"]])
        corrections=visible["version_corrections"]
        self.assertEqual([("add","3.2.1"),("remove","3.2.0")],[(c["action"],c["version_key"]) for c in corrections])
        self.assertTrue(all(c["reason"] for c in corrections))
        with self.assertRaisesRegex(DomainError,"至少保留一个"):
            self.db.correct_versions(self.report,self.coord,remove=["3.2.1"],reason="尝试移除全部版本")
        self._advance_to_resolved()
        self._approved_review()
        self.db.publish_report(self.report,self.coord,"2026-10-30")
        with self.assertRaisesRegex(DomainError,"已披露"):
            self.db.correct_versions(self.report,self.coord,add=["3.2.2"],reason="披露后不得再更正")
        advisory=self.db.get_advisory(self.report,self.outsider)
        self.assertEqual("published",advisory["status"])

if __name__=="__main__": unittest.main()
