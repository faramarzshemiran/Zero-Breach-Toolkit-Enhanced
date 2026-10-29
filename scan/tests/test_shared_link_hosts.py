"""A malicious link on a URL shortener or shared host must not turn the whole
service into a spyware indicator."""
import os
import tempfile
import unittest

from zbtriage import feeds

CSV_HEADER = "uuid,event_id,category,type,value,comment,to_ids,date\n"


class SharedLinkHosts(unittest.TestCase):
    def _load(self, rows):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "set.misp.csv")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(CSV_HEADER)
                for kind, value in rows:
                    fh.write('1,1,Network activity,{},"{}","",1,20170626\n'.format(kind, value))
            return feeds.load_list(path, "misp-csv", "test source", "Pegasus")

    def test_shortener_links_do_not_flag_the_shortener(self):
        loaded = self._load([("url", "http://bit.ly/2abcXYZ"),
                             ("url", "http://tinyurl.com/j7luz86"),
                             ("url", "https://docs.google.com/document/d/x"),
                             ("url", "http://smsmensaje.mx/abc"),
                             ("domain", "unonoticias.net")])
        values = {i.value for i in loaded.indicators}
        self.assertEqual(values, {"smsmensaje.mx", "unonoticias.net"})
        skipped = loaded.sets[0]["not_applicable_to_this_scan"]
        self.assertEqual(sum(skipped.values()), 3)

    def test_lookalikes_of_shared_hosts_are_still_indicators(self):
        loaded = self._load([("url", "http://twiitter.com.mx/a"),
                             ("url", "http://get.adobe.com.bowenpress.org/x"),
                             ("url", "http://bit.ly.evil.example/y")])
        values = {i.value for i in loaded.indicators}
        self.assertEqual(values, {"twiitter.com.mx", "get.adobe.com.bowenpress.org",
                                  "bit.ly.evil.example"})


if __name__ == "__main__":
    unittest.main()
