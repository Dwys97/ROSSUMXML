import React from 'react';
import { Link } from 'react-router-dom';
import TopNav from '../components/TopNav';
import Footer from '../components/common/Footer';
import styles from './LandingPage.module.css';

function LandingPage() {
  return (
    <>
      <TopNav />
      <div className={styles.hero}>
        <div className={styles.technicalGrid}></div>
        <div className={styles.scanLine}></div>

        <div className={styles.heroContent}>
          <div className={styles.systemBadge}>
            <div className={styles.statusDot}></div>
            System V3.0 // Ready
          </div>

          <h1 className={styles.heroTitle}>
            Schema <br /> Infrastructure
          </h1>

          <p className={styles.heroSubtitle}>
                        // UNIVERSAL TRANSLATOR<br />
            Map any XML structure to any other. <br />
            Zero-code JSON definitions. Infinite scale.
          </p>

          <div className={styles.ctaGroup}>
            <Link to="/transformer" className={styles.primaryBtn}>
              Initialize Layer
            </Link>
            <Link to="/docs" className={styles.secondaryBtn}>
              Documentation
            </Link>
          </div>
        </div>

        {/* THE ENGINE STAGE (3 COLUMNS) */}
        <div className={styles.engineStage}>

          {/* 1. SOURCE XML */}
          <div className={`${styles.codeStream} ${styles.sourceStream}`}>
            <div className={styles.streamHeader}>
              <span>Input Source</span>
              <span>XML</span>
            </div>
            <div className={styles.streamContent}>
              &lt;<span className={styles.tag}>LegacyOrder</span>&gt;<br />
              &nbsp;&nbsp;&lt;<span className={styles.tag}>Header</span>&gt;<br />
              &nbsp;&nbsp;&nbsp;&nbsp;&lt;<span className={styles.tag}>Ref</span>&gt;PO-992&lt;/<span className={styles.tag}>Ref</span>&gt;<br />
              &nbsp;&nbsp;&nbsp;&nbsp;&lt;<span className={styles.tag}>Dt</span>&gt;20260115&lt;/<span className={styles.tag}>Dt</span>&gt;<br />
              &nbsp;&nbsp;&lt;/<span className={styles.tag}>Header</span>&gt;<br />
              &nbsp;&nbsp;&lt;<span className={styles.tag}>Rows</span>&gt;<br />
              &nbsp;&nbsp;&nbsp;&nbsp;&lt;<span className={styles.tag}>Row</span>&gt;<br />
              &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&lt;<span className={styles.tag}>Sku</span>&gt;A-100&lt;/<span className={styles.tag}>Sku</span>&gt;<br />
              &nbsp;&nbsp;&nbsp;&nbsp;&lt;/<span className={styles.tag}>Row</span>&gt;<br />
              &nbsp;&nbsp;&lt;/<span className={styles.tag}>Rows</span>&gt;<br />
              &lt;/<span className={styles.tag}>LegacyOrder</span>&gt;
            </div>
          </div>

          {/* 2. THE MAP (ENGINE) */}
          <div className={`${styles.codeStream} ${styles.mapStream}`}>
            <div className={styles.streamHeader} style={{ color: 'var(--accent-orange)' }}>
              <span>Transformation Logic</span>
              <span>JSON MAP</span>
            </div>
            <div className={styles.streamContent}>
              &#123;<br />
              &nbsp;&nbsp;<span className={styles.comment}>// Map Header Fields</span><br />
              &nbsp;&nbsp;<span className={styles.key}>"NewOrder.ID"</span>: <span className={styles.str}>"LegacyOrder.Header.Ref"</span>,<br />
              &nbsp;&nbsp;<span className={styles.key}>"NewOrder.Date"</span>: <span className={styles.str}>"LegacyOrder.Header.Dt"</span>,<br />
              <br />
              &nbsp;&nbsp;<span className={styles.comment}>// Array Transformation</span><br />
              &nbsp;&nbsp;<span className={styles.key}>"NewOrder.Lines[]"</span>: &#123;<br />
              &nbsp;&nbsp;&nbsp;&nbsp;<span className={styles.key}>"$for"</span>: <span className={styles.str}>"LegacyOrder.Rows.Row"</span>,<br />
              &nbsp;&nbsp;&nbsp;&nbsp;<span className={styles.key}>"ItemCode"</span>: <span className={styles.str}>"$item.Sku"</span><br />
              &nbsp;&nbsp;&#125;<br />
              &#125;
            </div>
          </div>

          {/* 3. TARGET XML */}
          <div className={`${styles.codeStream} ${styles.targetStream}`}>
            <div className={styles.streamHeader}>
              <span>Final Output</span>
              <span>XML</span>
            </div>
            <div className={styles.streamContent}>
              &lt;<span className={styles.tag}>NewOrder</span>&gt;<br />
              &nbsp;&nbsp;&lt;<span className={styles.tag}>ID</span>&gt;PO-992&lt;/<span className={styles.tag}>ID</span>&gt;<br />
              &nbsp;&nbsp;&lt;<span className={styles.tag}>Date</span>&gt;2026-01-15&lt;/<span className={styles.tag}>Date</span>&gt;<br />
              &nbsp;&nbsp;&lt;<span className={styles.tag}>Lines</span>&gt;<br />
              &nbsp;&nbsp;&nbsp;&nbsp;&lt;<span className={styles.tag}>Line</span>&gt;<br />
              &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&lt;<span className={styles.tag}>ItemCode</span>&gt;A-100&lt;/<span className={styles.tag}>ItemCode</span>&gt;<br />
              &nbsp;&nbsp;&nbsp;&nbsp;&lt;/<span className={styles.tag}>Line</span>&gt;<br />
              &nbsp;&nbsp;&lt;/<span className={styles.tag}>Lines</span>&gt;<br />
              &lt;/<span className={styles.tag}>NewOrder</span>&gt;
            </div>
          </div>

          {/* SVG CONNECTIONS OVERLAY */}
          <svg className={styles.connectionCanvas} viewBox="0 0 1400 500" preserveAspectRatio="none">
            {/* Define Marker */}
            <defs>
              <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                <path d="M0,0 L0,6 L6,3 z" fill="var(--accent-orange)" />
              </marker>
            </defs>

            {/* Path 1: Source Ref -> Map ID */}
            <path className={styles.activeLine} d="M 330 140 C 450 140, 450 150, 560 150" />
            <circle r="3" className={styles.dataPacket}>
              <animateMotion dur="2s" repeatCount="indefinite" path="M 330 140 C 450 140, 450 150, 560 150" />
            </circle>

            {/* Path 2: Map ID -> Target ID */}
            <path className={styles.activeLine} d="M 870 150 C 980 150, 980 140, 1080 140" />
            <circle r="3" className={styles.dataPacket}>
              <animateMotion dur="2s" begin="1s" repeatCount="indefinite" path="M 870 150 C 980 150, 980 140, 1080 140" />
            </circle>

            {/* Path 3: Source Sku -> Map ItemCode */}
            <path className={styles.activeLine} d="M 330 250 C 450 250, 450 280, 560 280" />
            <circle r="3" className={styles.dataPacket}>
              <animateMotion dur="2.5s" begin="0.5s" repeatCount="indefinite" path="M 330 250 C 450 250, 450 280, 560 280" />
            </circle>

            {/* Path 4: Map ItemCode -> Target ItemCode */}
            <path className={styles.activeLine} d="M 870 280 C 980 280, 980 250, 1080 250" />
            <circle r="3" className={styles.dataPacket}>
              <animateMotion dur="2.5s" begin="1.5s" repeatCount="indefinite" path="M 870 280 C 980 280, 980 250, 1080 250" />
            </circle>

          </svg>

        </div>

        {/* ANIMATED TICKER */}
        <div className={styles.tickerSection}>
          <div className={styles.tickerTrack}>
            <div className={styles.tickerItem}>HIGH FREQUENCY TRADING SUPPORTED</div>
            <div className={styles.tickerItem}>//</div>
            <div className={styles.tickerItem}>SOC2 TYPE II COMPLIANT</div>
            <div className={styles.tickerItem}>//</div>
            <div className={styles.tickerItem}>99.999% UPTIME SLA</div>
            <div className={styles.tickerItem}>//</div>
            <div className={styles.tickerItem}>ISO 27001 CERTIFIED</div>
            <div className={styles.tickerItem}>//</div>
          </div>
        </div>

        {/* SECTION 1: SYSTEM CAPABILITIES */}
        <section className={styles.section}>
          <div className={styles.sectionHeader}>
            <span className={styles.sectionLabel}>System Architecture</span>
            <h2 className={styles.sectionTitle}>SchemaBridge Core</h2>
          </div>
          <div className={styles.grid3x2}>
            <div className={styles.gridItem}>
              <div className={styles.itemIcon}>[IO]</div>
              <span className={styles.itemHeader}>01 // STREAMING_PARSER</span>
              <h3 className={styles.itemTitle}>Zero-Latency Ingest</h3>
              <p className={styles.itemDesc}>Process gigabyte-scale XML streams without memory overhead using SAX-based event architecture.</p>
            </div>
            <div className={styles.gridItem}>
              <div className={styles.itemIcon}>[MAP]</div>
              <span className={styles.itemHeader}>02 // FLUID_MAPPING</span>
              <h3 className={styles.itemTitle}>Declarative JSON Logic</h3>
              <p className={styles.itemDesc}>Define complex transformations in simple JSON. No XSLT. No compilation steps.</p>
            </div>
            <div className={styles.gridItem}>
              <div className={styles.itemIcon}>[VAL]</div>
              <span className={styles.itemHeader}>03 // SCHEMA_GUARD</span>
              <h3 className={styles.itemTitle}>Strict Validation</h3>
              <p className={styles.itemDesc}>Enforce XSD and JSON Schema constraints in real-time. Reject malformed payloads instantly.</p>
            </div>
            <div className={styles.gridItem}>
              <div className={styles.itemIcon}>[API]</div>
              <span className={styles.itemHeader}>04 // REST_INTERFACE</span>
              <h3 className={styles.itemTitle}>Headless Integration</h3>
              <p className={styles.itemDesc}>Full API control. Embed transformation logic directly into your microservices.</p>
            </div>
            <div className={styles.gridItem}>
              <div className={styles.itemIcon}>[SEC]</div>
              <span className={styles.itemHeader}>05 // VAULT_SECURITY</span>
              <h3 className={styles.itemTitle}>Immutable Audit Logs</h3>
              <p className={styles.itemDesc}>Every transformation is cryptographically signed and logged for compliance.</p>
            </div>
            <div className={styles.gridItem}>
              <div className={styles.itemIcon}>[SDK]</div>
              <span className={styles.itemHeader}>06 // DEV_TOOLKIT</span>
              <h3 className={styles.itemTitle}>TypeScript Native</h3>
              <p className={styles.itemDesc}>First-class type definitions generated automatically from your schema maps.</p>
            </div>
          </div>
        </section>

        {/* SECTION 2: ENTROPY SCALE */}
        <section className={styles.section}>
          <div className={styles.sectionHeader}>
            <span className={styles.sectionLabel}>The Problem</span>
            <h2 className={styles.sectionTitle}>Entropy Management</h2>
          </div>
          <div className={styles.entropyContainer}>
            <div className={`${styles.entropyBlock} ${styles.chaos}`}>
              <span className={styles.scaleLabel}>Legacy System (Entropy: HIGH)</span>
              <div className={styles.glitchText}>
                &lt;Order_X99&gt;<br />
                &nbsp;&nbsp;&lt;uNkown_Tag&gt;ERR#404&lt;/...&gt;<br />
                &nbsp;&nbsp;&lt;DATA type="bloated"&gt;<br />
                &nbsp;&nbsp;&nbsp;&nbsp;...legacy_payload_overflow...<br />
                &nbsp;&nbsp;&lt;/DATA&gt;<br />
                &lt;/Order_X99&gt;
              </div>
            </div>
            <div className={`${styles.entropyBlock} ${styles.order}`}>
              <span className={styles.scaleLabel}>SchemaBridge (Entropy: ZERO)</span>
              <div className={styles.cleanText}>
                &#123;<br />
                &nbsp;&nbsp;"id": "ORD-2026-X99",<br />
                &nbsp;&nbsp;"status": "CLEAN",<br />
                &nbsp;&nbsp;"payload": &#123;<br />
                &nbsp;&nbsp;&nbsp;&nbsp;"verified": true,<br />
                &nbsp;&nbsp;&nbsp;&nbsp;"optimized": true<br />
                &nbsp;&nbsp;&#125;<br />
                &#125;
              </div>
            </div>
          </div>
        </section>

        {/* SECTION 3: TERMINAL DEMO */}
        <section className={styles.section}>
          <div className={styles.sectionHeader}>
            <span className={styles.sectionLabel}>Developer Access</span>
            <h2 className={styles.sectionTitle}>CLI Control</h2>
          </div>
          <div className={styles.terminalWindow}>
            <div className={styles.terminalHeader}>
              <div className={`${styles.dot} ${styles.red}`}></div>
              <div className={`${styles.dot} ${styles.yellow}`}></div>
              <div className={`${styles.dot} ${styles.green}`}></div>
            </div>
            <div className={styles.terminalBody}>
              <div><span className={styles.prompt}>admin@server:~$</span><span className={styles.cmd}>npm install @schemabridge/core</span></div>
              <span className={styles.output}>+ @schemabridge/core@3.0.0 installed in 1.4s</span>

              <div><span className={styles.prompt}>admin@server:~$</span><span className={styles.cmd}>schemabridge map --src legacy.xml --out standardized.json</span></div>
              <span className={styles.output}>> Parsing XML stream... OK</span>
              <span className={styles.output}>> Applying 'Standard-V3' map... OK</span>
              <span className={styles.output}>> Validating Schema... OK</span>
              <span className={styles.output}>✓ Transformation complete (12ms)</span>

              <div><span className={styles.prompt}>admin@server:~$</span><span className={styles.cursor}></span></div>
            </div>
          </div>
        </section>

        {/* SECTION 4: CONNECTIVITY */}
        <section className={styles.section}>
          <div className={styles.sectionHeader}>
            <span className={styles.sectionLabel}>Integration Network</span>
            <h2 className={styles.sectionTitle}>Universal Adapter</h2>
          </div>
          <div className={styles.networkContainer}>
            {/* Static SVG Lines representation */}
            <svg style={{ position: 'absolute', width: '100%', height: '100%' }}>
              <line x1="50%" y1="50%" x2="20%" y2="20%" stroke="#1a1a1a" strokeWidth="1" />
              <line x1="50%" y1="50%" x2="80%" y2="20%" stroke="#1a1a1a" strokeWidth="1" />
              <line x1="50%" y1="50%" x2="30%" y2="80%" stroke="#1a1a1a" strokeWidth="1" />
              <line x1="50%" y1="50%" x2="70%" y2="80%" stroke="#1a1a1a" strokeWidth="1" />
            </svg>

            <div className={styles.hubNode}>
              <svg className={styles.hubIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
              </svg>
            </div>

            <div className={`${styles.satelliteNode} ${styles.sat1}`}>SAP ERP</div>
            <div className={`${styles.satelliteNode} ${styles.sat2}`}>SALESFORCE</div>
            <div className={`${styles.satelliteNode} ${styles.sat3}`}>ORACLE NETSUITE</div>
            <div className={`${styles.satelliteNode} ${styles.sat4}`}>CUSTOM API</div>
          </div>
        </section>

        {/* SECTION 5: LOGS (Testimonials) */}
        <section className={styles.section}>
          <div className={styles.sectionHeader}>
            <span className={styles.sectionLabel}>Transmission Logs</span>
            <h2 className={styles.sectionTitle}>System Reports</h2>
          </div>
          <div className={styles.logsContainer}>
            <div className={styles.logEntry}>
              <span className={styles.logTime}>2026-01-12 14:00</span>
              <span className={styles.logStatus}>[SUCCESS]</span>
              <div>
                <span className={styles.logMessage}>"Migration logic reduced from 4 weeks to 2 days."</span>
                <span className={styles.logAuthor}>// CTO, FinTech Global</span>
              </div>
            </div>
            <div className={styles.logEntry}>
              <span className={styles.logTime}>2026-01-12 14:05</span>
              <span className={styles.logStatus}>[SUCCESS]</span>
              <div>
                <span className={styles.logMessage}>"SchemaBridge handles our Black Friday load (50k req/s) without jitter."</span>
                <span className={styles.logAuthor}>// Lead Engineer, E-Comm Giant</span>
              </div>
            </div>
            <div className={styles.logEntry}>
              <span className={styles.logTime}>2026-01-12 14:10</span>
              <span className={styles.logStatus}>[SUCCESS]</span>
              <div>
                <span className={styles.logMessage}>"The JSON mapping engine is exactly what the industry needed."</span>
                <span className={styles.logAuthor}>// Solutions Architect, Logistics Co.</span>
              </div>
            </div>
          </div>
        </section>

        <Footer />
      </div>
    </>
  );
}

export default LandingPage;
