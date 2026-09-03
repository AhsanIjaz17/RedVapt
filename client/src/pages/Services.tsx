import React, { useEffect, useRef, useCallback } from 'react';
import {
    Shield,
    Search,
    Target,
    FileText,
    Lock,
    Zap,
    CheckCircle2,
    ChevronRight,
    ArrowRight,
    Globe,
    Terminal,
    Activity,
    AlertTriangle,
    Eye,
    Code2,
    Server,
    Bug,
    Users,
    MessageSquare,
    Crosshair,
    Award
} from 'lucide-react';

// Assets — user-provided certification badges
import badgeOscp from '../assets/badge-oscp.png';
import badgeOswe from '../assets/badge-oswe.png';
import badgeEwpt from '../assets/badge-ewpt.png';
import badgeCpts from '../assets/badge-cpts.png';
import badgeOswa from '../assets/badge-oswa.png';

/* ─────────────────────────────────────────────
   Inline styles — no external CSS file needed
   ───────────────────────────────────────────── */
const SERVICES_STYLES = `
  .services-page .animate-on-scroll {
    opacity: 0;
    transform: translateY(40px);
    transition: opacity 0.8s cubic-bezier(0.16, 1, 0.3, 1),
                transform 0.8s cubic-bezier(0.16, 1, 0.3, 1);
  }
  .services-page .animate-on-scroll.is-visible {
    opacity: 1;
    transform: translateY(0);
  }
  .services-page .stagger-1 { transition-delay: 0.05s; }
  .services-page .stagger-2 { transition-delay: 0.12s; }
  .services-page .stagger-3 { transition-delay: 0.19s; }
  .services-page .stagger-4 { transition-delay: 0.26s; }
  .services-page .stagger-5 { transition-delay: 0.33s; }
  .services-page .stagger-6 { transition-delay: 0.40s; }
  .services-page .stagger-7 { transition-delay: 0.47s; }
  .services-page .stagger-8 { transition-delay: 0.54s; }

  .services-page .slide-in-left {
    opacity: 0;
    transform: translateX(-60px);
    transition: opacity 0.7s cubic-bezier(0.16, 1, 0.3, 1),
                transform 0.7s cubic-bezier(0.16, 1, 0.3, 1);
  }
  .services-page .slide-in-left.is-visible {
    opacity: 1;
    transform: translateX(0);
  }
  .services-page .slide-in-right {
    opacity: 0;
    transform: translateX(60px);
    transition: opacity 0.7s cubic-bezier(0.16, 1, 0.3, 1),
                transform 0.7s cubic-bezier(0.16, 1, 0.3, 1);
  }
  .services-page .slide-in-right.is-visible {
    opacity: 1;
    transform: translateX(0);
  }
  .services-page .scale-in {
    opacity: 0;
    transform: scale(0.85);
    transition: opacity 0.6s cubic-bezier(0.16, 1, 0.3, 1),
                transform 0.6s cubic-bezier(0.16, 1, 0.3, 1);
  }
  .services-page .scale-in.is-visible {
    opacity: 1;
    transform: scale(1);
  }

  @keyframes svc-float {
    0%, 100% { transform: translateY(0); }
    50%      { transform: translateY(-8px); }
  }
  .services-page .float-animation {
    animation: svc-float 6s ease-in-out infinite;
  }

  @keyframes svc-pulse-glow {
    0%, 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
    50%      { box-shadow: 0 0 30px 4px rgba(239, 68, 68, 0.15); }
  }
  .services-page .pulse-glow {
    animation: svc-pulse-glow 4s ease-in-out infinite;
  }

  @keyframes svc-shimmer {
    0%   { background-position: -200% 0; }
    100% { background-position: 200% 0; }
  }
  .services-page .shimmer-text {
    background-size: 200% auto;
    animation: svc-shimmer 3s linear infinite;
  }

  .services-page .cert-badge {
    transition: transform 0.35s cubic-bezier(0.16, 1, 0.3, 1),
                box-shadow 0.35s ease,
                border-color 0.35s ease;
  }
  .services-page .cert-badge:hover {
    transform: translateY(-6px) scale(1.03);
    box-shadow: 0 20px 40px -12px rgba(0, 0, 0, 0.5);
  }
  .services-page .cert-badge img {
    transition: filter 0.4s ease, transform 0.4s ease;
    filter: brightness(0.95);
  }
  .services-page .cert-badge:hover img {
    filter: brightness(1.1) drop-shadow(0 0 8px rgba(255, 255, 255, 0.15));
    transform: scale(1.08);
  }

  .services-page .timeline-line { position: relative; }
  .services-page .timeline-line::after {
    content: '';
    position: absolute;
    top: 0; left: 50%; transform: translateX(-50%);
    width: 2px; height: 100%;
    background: linear-gradient(180deg, transparent 0%, rgba(238, 67, 68,0.25) 20%, rgba(238, 67, 68,0.4) 50%, rgba(252,165,165,0.35) 80%, transparent 100%);
  }

  .services-page .step-number { transition: all 0.35s ease; }
  .services-page .step-card:hover .step-number {
    background: linear-gradient(135deg, #FB7185, #EE4344);
    color: #fff;
    transform: scale(1.15);
    box-shadow: 0 0 20px rgba(239, 68, 68, 0.4);
  }
  .services-page .step-card {
    transition: border-color 0.3s ease, background-color 0.3s ease, transform 0.3s ease;
  }
  .services-page .step-card:hover {
    border-color: rgba(238, 67, 68, 0.35);
    background-color: rgba(15, 23, 42, 0.8);
    transform: translateX(4px);
  }

  .services-page .vuln-pill {
    transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
  }
  .services-page .vuln-pill:hover {
    transform: translateY(-3px);
    box-shadow: 0 8px 24px -8px rgba(238, 67, 68, 0.35);
    border-color: rgba(238, 67, 68, 0.45);
    background: rgba(238, 67, 68, 0.08);
  }

  @keyframes svc-orb-drift {
    0%, 100% { transform: translate(0, 0) scale(1); }
    25%      { transform: translate(30px, -20px) scale(1.05); }
    50%      { transform: translate(-15px, 15px) scale(0.97); }
    75%      { transform: translate(20px, 10px) scale(1.02); }
  }
  .services-page .orb {
    animation: svc-orb-drift 20s ease-in-out infinite;
  }

  @keyframes svc-blink {
    0%, 100% { opacity: 1; }
    50%      { opacity: 0; }
  }
  .services-page .cursor-blink {
    animation: svc-blink 1s step-end infinite;
  }

  .services-page .counter-value {
    display: inline-block;
    font-variant-numeric: tabular-nums;
  }
`;

/* ─────────────────────────────────────────────
   Intersection Observer Hook for animations
   ───────────────────────────────────────────── */
function useScrollReveal() {
    const observer = useRef<IntersectionObserver | null>(null);

    const init = useCallback(() => {
        if (observer.current) return;
        observer.current = new IntersectionObserver(
            (entries) => {
                entries.forEach((entry) => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('is-visible');
                    }
                });
            },
            { threshold: 0.12, rootMargin: '0px 0px -40px 0px' }
        );

        document.querySelectorAll('.services-page .animate-on-scroll, .services-page .slide-in-left, .services-page .slide-in-right, .services-page .scale-in')
            .forEach((el) => observer.current?.observe(el));
    }, []);

    useEffect(() => {
        // Small delay to ensure DOM is ready
        const timer = setTimeout(init, 100);
        return () => {
            clearTimeout(timer);
            observer.current?.disconnect();
        };
    }, [init]);
}

/* ─────────────────────────────────────────────
   Animated Counter Component
   ───────────────────────────────────────────── */
const AnimatedCounter: React.FC<{ end: number; suffix?: string; duration?: number }> = ({
    end, suffix = '', duration = 2000
}) => {
    const ref = useRef<HTMLSpanElement>(null);
    const counted = useRef(false);

    useEffect(() => {
        const el = ref.current;
        if (!el) return;

        const io = new IntersectionObserver(([entry]) => {
            if (entry.isIntersecting && !counted.current) {
                counted.current = true;
                let start = 0;
                const step = end / (duration / 16);
                const tick = () => {
                    start += step;
                    if (start >= end) {
                        el.textContent = `${end}${suffix}`;
                        return;
                    }
                    el.textContent = `${Math.floor(start)}${suffix}`;
                    requestAnimationFrame(tick);
                };
                requestAnimationFrame(tick);
            }
        }, { threshold: 0.5 });

        io.observe(el);
        return () => io.disconnect();
    }, [end, suffix, duration]);

    return <span ref={ref} className="counter-value">0{suffix}</span>;
};

/* ─────────────────────────────────────────────
   Data
   ───────────────────────────────────────────── */
const methodology = [
    {
        step: '01',
        title: 'Pre-Engagement Interactions',
        description: 'A series of email exchanges and meetings will take place prior to testing. This is to finalize the scope and rules of engagement for the testing and answer any questions that the stakeholders might have concerning the process.',
        icon: <MessageSquare size={22} />,
        accent: '#EE4344'
    },
    {
        step: '02',
        title: 'Intelligence Gathering',
        description: 'The assessor will perform scans on the Web Application which includes a NMAP port and an online search for any resources such as GitHub repositories, open-source coding involvement, other websites, etc. of the developers.',
        icon: <Search size={22} />,
        accent: '#F87171'
    },
    {
        step: '03',
        title: 'Threat Modeling',
        description: 'After reviewing the information gathered during the two previous phases, the assessor will determine the main assets that the Web Application should protect and how those assets might be attacked.',
        icon: <Crosshair size={22} />,
        accent: '#F43F5E'
    },
    {
        step: '04',
        title: 'Vulnerability Analysis',
        description: 'The assessor will use industry standard tools (Nikto, Skipfish, etc.) as well as publicly available sources of information (exploit-db, CVE, etc.) to look for any weaknesses or vulnerabilities on the systems.',
        icon: <Bug size={22} />,
        accent: '#EE4344'
    },
    {
        step: '05',
        title: 'Exploitation & Post-Exploitation',
        description: 'The assessor will mount various attacks to bypass security restrictions. The main tool used during a Web Application pentest will be Burp Suite Pro which will be augmented with other tools as needed. The results of these tests and other vulnerabilities will be presented in a report.',
        icon: <Terminal size={22} />,
        accent: '#DC2626'
    }
];

const vulnerabilities = [
    { name: 'Broken Access Control', icon: <Lock size={18} /> },
    { name: 'Injections (SQL, NoSQL, OS)', icon: <Code2 size={18} /> },
    { name: 'Security Misconfigurations', icon: <Server size={18} /> },
    { name: 'Sensitive Data Exposure', icon: <Eye size={18} /> },
    { name: 'Cross-Site Scripting (XSS)', icon: <AlertTriangle size={18} /> },
    { name: 'Server-Side Request Forgery', icon: <Globe size={18} /> },
    { name: 'Cross-Site Request Forgery', icon: <Shield size={18} /> },
    { name: 'Business Logic Flaws', icon: <Activity size={18} /> },
];

const certifications = [
    {
        img: badgeOscp,
        name: 'OSCP',
        full: 'Offensive Security Certified Professional',
        org: 'OffSec',
        color: '#e5792a'
    },
    {
        img: badgeOswe,
        name: 'OSWE',
        full: 'OffSec Web Expert',
        org: 'OffSec',
        color: '#14b8a6'
    },
    {
        img: badgeEwpt,
        name: 'eWPT',
        full: 'Web Application Penetration Tester',
        org: 'INE Security',
        color: '#ec4899'
    },
    {
        img: badgeCpts,
        name: 'CPTS',
        full: 'Certified Penetration Testing Specialist',
        org: 'HackTheBox',
        color: '#7c3aed'
    },
    {
        img: badgeOswa,
        name: 'OSWA',
        full: 'OffSec Web Assessor',
        org: 'OffSec',
        color: '#e84a76'
    }
];

/* ─────────────────────────────────────────────
   Services Component
   ───────────────────────────────────────────── */
const Services: React.FC = () => {
    useScrollReveal();

    return (
        <div className="services-page bg-[#020617] text-slate-100 min-h-screen">
            {/* Inline scoped styles — no external CSS file needed */}
            <style dangerouslySetInnerHTML={{ __html: SERVICES_STYLES }} />

            {/* ═══════════════════════ HERO ═══════════════════════ */}
            <section className="relative overflow-hidden pt-32 pb-24 px-6 lg:px-12">
                {/* Background orbs */}
                <div className="absolute top-[-10%] left-[-5%] w-[500px] h-[500px] bg-red-600/8 rounded-full blur-[140px] orb" />
                <div className="absolute bottom-[-10%] right-[-5%] w-[400px] h-[400px] bg-brand/10 rounded-full blur-[120px] orb" style={{ animationDelay: '-7s' }} />

                <div className="max-w-6xl mx-auto relative z-10">
                    <div className="animate-on-scroll text-center space-y-8">
                        {/* Badge */}
                        <div className="inline-flex items-center gap-2 px-5 py-2 rounded-full border border-slate-800 bg-slate-900/60 backdrop-blur-sm">
                            <Shield size={14} className="text-red-500" />
                            <span className="text-xs font-semibold text-slate-400 uppercase tracking-[0.2em]">Manual Penetration Testing</span>
                        </div>

                        {/* Headline */}
                        <h1 className="text-5xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight leading-[1.1]">
                            <span className="block text-white">Professional Web Application</span>
                            <span className="block mt-2 text-transparent bg-clip-text bg-gradient-to-r from-red-500 via-red-400 to-red-600 shimmer-text"
                                style={{ backgroundImage: 'linear-gradient(90deg, #EE4344, #FCA5A5, #EE4344, #F87171, #EE4344)', backgroundSize: '200% auto' }}>
                                Penetration Testing
                            </span>
                        </h1>

                        <p className="text-slate-400 text-lg sm:text-xl max-w-3xl mx-auto leading-relaxed font-normal">
                            Our certified security professionals go beyond automated scanning — manually probing
                            your applications for complex vulnerabilities, business logic flaws, and multi-step
                            attack chains that tools miss.
                        </p>

                        {/* CTA Buttons */}
                        <div className="flex flex-wrap justify-center gap-4 pt-4">
                            <a
                                href="#methodology"
                                className="group inline-flex items-center gap-2.5 px-8 py-4 bg-brand hover:bg-red-700 text-white rounded-xl font-semibold transition-all duration-300 hover:shadow-[0_8px_30px_-4px_rgba(238, 67, 68,0.45)] active:scale-[0.97]"
                            >
                                Our Methodology
                                <ChevronRight size={18} className="transition-transform group-hover:translate-x-0.5" />
                            </a>
                            <a
                                href="#contact"
                                className="inline-flex items-center gap-2.5 px-8 py-4 bg-slate-900/80 border border-slate-700/60 hover:border-slate-600 text-white rounded-xl font-semibold transition-all duration-300 hover:bg-slate-800/80"
                            >
                                <FileText size={18} className="text-slate-400" />
                                Request a Quote
                            </a>
                        </div>
                    </div>

                    {/* Stats row */}
                    <div className="animate-on-scroll stagger-2 mt-20 grid grid-cols-2 md:grid-cols-4 gap-6 max-w-4xl mx-auto">
                        {[
                            { value: 150, suffix: '+', label: 'Applications Tested' },
                            { value: 98, suffix: '%', label: 'Client Satisfaction' },
                            { value: 5, suffix: '+', label: 'Industry Certifications' },
                            { value: 12, suffix: '+', label: 'Years of Experience' },
                        ].map((stat, i) => (
                            <div key={i} className="text-center p-6 rounded-2xl bg-slate-900/30 border border-slate-800/50 hover:border-slate-700/60 transition-colors">
                                <div className="text-3xl sm:text-4xl font-extrabold text-white">
                                    <AnimatedCounter end={stat.value} suffix={stat.suffix} />
                                </div>
                                <p className="text-sm text-slate-500 mt-2 font-medium">{stat.label}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ═══════════════════════ METHODOLOGY ═══════════════════════ */}
            <section id="methodology" className="py-28 px-6 relative">
                <div className="absolute inset-0 bg-gradient-to-b from-transparent via-slate-950/50 to-transparent pointer-events-none" />

                <div className="max-w-6xl mx-auto relative z-10">
                    {/* Section header */}
                    <div className="animate-on-scroll text-center mb-20">
                        <span className="text-xs font-bold text-red-500/80 uppercase tracking-[0.3em] block mb-4">Our Process</span>
                        <h2 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight">
                            How Is A Penetration Test Done?
                        </h2>
                        <p className="text-slate-400 text-lg max-w-2xl mx-auto mt-6 leading-relaxed">
                            We follow a proven 5-phase methodology that ensures thorough coverage
                            and actionable results every engagement.
                        </p>
                    </div>

                    {/* Timeline */}
                    <div className="relative">
                        {/* Vertical connector line — visible on md+ */}
                        <div className="hidden md:block absolute left-8 top-0 bottom-0 w-px timeline-line" />

                        <div className="space-y-6">
                            {methodology.map((item, idx) => (
                                <div
                                    key={idx}
                                    className={`animate-on-scroll stagger-${idx + 1} step-card relative flex gap-6 md:gap-10 items-start p-8 rounded-2xl border border-slate-800/60 bg-slate-900/20 hover:bg-slate-900/40`}
                                >
                                    {/* Step number */}
                                    <div
                                        className="step-number flex-shrink-0 w-16 h-16 rounded-2xl flex items-center justify-center font-extrabold text-lg border border-slate-700/50 bg-slate-900/80 relative z-10"
                                        style={{ color: item.accent }}
                                    >
                                        {item.step}
                                    </div>

                                    {/* Content */}
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-3 mb-3">
                                            <span style={{ color: item.accent }}>{item.icon}</span>
                                            <h3 className="text-xl sm:text-2xl font-bold text-white">{item.title}</h3>
                                        </div>
                                        <p className="text-slate-400 leading-relaxed text-[15px]">{item.description}</p>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Additional context paragraph */}
                    <div className="animate-on-scroll mt-14 p-8 rounded-2xl border border-brand/20 bg-brand/5 max-w-4xl mx-auto">
                        <p className="text-slate-300 leading-relaxed text-[15px]">
                            <strong className="text-brand">During the Vulnerability Analysis and Exploitation/Post-Exploitation phases</strong>, the assessor will test for common web application vulnerabilities including, but not limited to:{' '}
                            <span className="text-slate-400">
                                Broken Access Control, Injections, Security Misconfigurations, Sensitive Data Exposure,
                                Cross-Site Scripting, Server-Side Request Forgery, Cross-Site Request Forgery, and Business Logic Flaws.
                            </span>
                        </p>
                    </div>
                </div>
            </section>

            {/* ═══════════════════════ VULNERABILITIES WE TEST ═══════════════════════ */}
            <section className="py-24 px-6 bg-slate-950/40">
                <div className="max-w-6xl mx-auto">
                    <div className="animate-on-scroll text-center mb-16">
                        <span className="text-xs font-bold text-slate-500 uppercase tracking-[0.3em] block mb-4">Coverage</span>
                        <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight">
                            Vulnerabilities We Test For
                        </h2>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                        {vulnerabilities.map((vuln, idx) => (
                            <div
                                key={idx}
                                className={`animate-on-scroll stagger-${idx + 1} vuln-pill flex items-center gap-3 px-5 py-4 rounded-xl border border-slate-800/60 bg-slate-900/30 cursor-default`}
                            >
                                <span className="text-brand flex-shrink-0">{vuln.icon}</span>
                                <span className="text-sm font-medium text-slate-300">{vuln.name}</span>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ═══════════════════════ VERIFIED EXPERTISE — Certifications ═══════════════════════ */}
            <section className="py-28 px-6 relative">
                <div className="absolute inset-0 bg-gradient-to-b from-transparent via-slate-900/30 to-transparent pointer-events-none" />

                <div className="max-w-6xl mx-auto relative z-10">
                    <div className="animate-on-scroll text-center mb-16">
                        <div className="inline-flex items-center gap-2 mb-4">
                            <Award size={16} className="text-amber-500" />
                            <span className="text-xs font-bold text-amber-500/80 uppercase tracking-[0.3em]">Verified Expertise</span>
                        </div>
                        <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight">
                            Certified Security Professionals
                        </h2>
                        <p className="text-slate-400 text-base max-w-xl mx-auto mt-4 leading-relaxed">
                            Our team holds industry-recognized certifications that validate deep expertise in offensive security.
                        </p>
                    </div>

                    {/* Certification grid — pentest-tools inspired layout */}
                    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-5">
                        {certifications.map((cert, idx) => (
                            <div
                                key={idx}
                                className={`animate-on-scroll stagger-${idx + 1} cert-badge group flex flex-col items-center text-center p-6 rounded-2xl border border-slate-800/50 bg-slate-900/20 hover:border-opacity-60 h-full`}
                                style={{ '--cert-color': cert.color } as React.CSSProperties}
                            >
                                {/* Badge image */}
                                <div className="w-24 h-24 mb-6 flex items-center justify-center overflow-hidden">
                                    <img
                                        src={cert.img}
                                        alt={cert.name}
                                        className="w-full h-full object-contain"
                                    />
                                </div>

                                {/* Content area with fixed heights for alignment */}
                                <div className="flex flex-col flex-1 w-full">
                                    <h4
                                        className="text-xl font-extrabold mb-2 transition-colors duration-300 h-8 flex items-center justify-center text-center"
                                        style={{ color: cert.color }}
                                    >
                                        {cert.name}
                                    </h4>

                                    <p className="text-xs text-slate-400 leading-snug mb-4 min-h-[40px] flex items-center justify-center px-1">
                                        {cert.full}
                                    </p>

                                    <div className="mt-auto">
                                        <span className="inline-block text-[10px] font-semibold uppercase tracking-widest text-slate-500 px-3 py-1 rounded-full bg-slate-800/60 border border-slate-700/40">
                                            {cert.org}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ═══════════════════════ WHY CHOOSE US ═══════════════════════ */}
            <section className="py-24 px-6 bg-slate-950/30">
                <div className="max-w-6xl mx-auto">
                    <div className="animate-on-scroll text-center mb-16">
                        <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight">
                            Why Choose Our Manual Testing?
                        </h2>
                    </div>

                    <div className="grid md:grid-cols-3 gap-6">
                        {[
                            {
                                icon: <Target size={24} className="text-red-400" />,
                                title: 'Beyond Automated Scanners',
                                desc: 'We identify complex business logic flaws, multi-step exploit chains, and authentication bypasses that automated tools cannot detect.',
                                border: 'border-red-500/10 hover:border-red-500/25'
                            },
                            {
                                icon: <Shield size={24} className="text-brand" />,
                                title: 'Proof-Based Reporting',
                                desc: 'Every vulnerability comes with verified proof of exploitation, detailed reproduction steps, and ready-to-run commands — no false positives.',
                                border: 'border-brand/10 hover:border-brand/25'
                            },
                            {
                                icon: <CheckCircle2 size={24} className="text-emerald-400" />,
                                title: 'Compliance Mapping',
                                desc: 'Findings are mapped directly to OWASP Top 10, PCI-DSS, SOC 2, and HIPAA requirements to streamline your remediation and audit processes.',
                                border: 'border-emerald-500/10 hover:border-emerald-500/25'
                            }
                        ].map((item, idx) => (
                            <div
                                key={idx}
                                className={`animate-on-scroll stagger-${idx + 1} p-8 rounded-2xl border ${item.border} bg-slate-900/20 transition-all duration-300 hover:bg-slate-900/40`}
                            >
                                <div className="p-3 bg-slate-800/50 rounded-xl w-fit mb-5">{item.icon}</div>
                                <h3 className="text-xl font-bold text-white mb-3">{item.title}</h3>
                                <p className="text-slate-400 text-sm leading-relaxed">{item.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ═══════════════════════ CTA ═══════════════════════ */}
            <section id="contact" className="py-32 px-6 relative overflow-hidden">
                <div className="absolute inset-0 pointer-events-none">
                    <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-red-600/5 rounded-full blur-[160px]" />
                </div>

                <div className="max-w-3xl mx-auto relative z-10">
                    <div className="animate-on-scroll scale-in text-center p-12 sm:p-16 rounded-3xl border border-slate-800/60 bg-slate-900/30 backdrop-blur-sm">
                        <h2 className="text-4xl sm:text-5xl font-extrabold tracking-tight leading-tight mb-6">
                            Ready for a <span className="text-red-500">Professional</span>{' '}
                            <br className="hidden sm:block" />
                            Security Assessment?
                        </h2>
                        <p className="text-slate-400 text-lg max-w-xl mx-auto mb-10 leading-relaxed">
                            Let our certified professionals find what automated tools miss.
                            Get a detailed report with actionable remediation guidance.
                        </p>
                        <div className="flex flex-wrap justify-center gap-4">
                            <button className="group inline-flex items-center gap-2.5 px-10 py-4 bg-white text-slate-950 rounded-xl font-bold transition-all duration-300 hover:shadow-[0_12px_40px_-8px_rgba(255,255,255,0.15)] hover:scale-[1.03] active:scale-[0.97]">
                                Book a Strategy Call
                                <ArrowRight size={20} className="transition-transform group-hover:translate-x-1" />
                            </button>
                            <button className="px-10 py-4 bg-slate-800/60 border border-slate-700/50 hover:border-slate-600 text-white rounded-xl font-bold transition-all duration-300 hover:bg-slate-800">
                                View Pricing
                            </button>
                        </div>
                    </div>
                </div>
            </section>
        </div>
    );
};

export default Services;
