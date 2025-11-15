if __name__ == "__main__":
    analyzer = FirewallAnalyzer("data/sample_firewall.log")
    analyzer.parse_log()
    analyzer.export_results()
