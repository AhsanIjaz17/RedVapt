import React, { useState } from 'react';
import {
    ShieldAlert,
    Search,
    Bug,
    Lock,
    Globe,
    Database,
    Server,
    Cpu,
    Code,
    Cloud,
    Key,
    Activity,
    ChevronRight,
    Filter
} from 'lucide-react';

interface VulnType {
    id: string;
    title: string;
    description: string;
    risk: 'Critical' | 'High' | 'Medium' | 'Low';
    category: 'Web' | 'Network' | 'API' | 'Cloud' | 'Logic';
    icon: React.ReactNode;
    tags: string[];
}

const vulnerabilityCatalog: VulnType[] = [
    {
        id: 'sqli',
        title: 'SQL Injection',
        description: 'Allows attackers to interfere with the queries that an application makes to its database, potentially revealing sensitive data or granting unauthorized access.',
        risk: 'Critical',
        category: 'Web',
        icon: <Database className="text-red-400" />,
        tags: ['CWE-89', 'Persistence', 'Data Breach']
    },
    {
        id: 'xss',
        title: 'Cross-Site Scripting (XSS)',
        description: 'Enables attackers to inject malicious scripts into web pages viewed by other users, leading to session hijacking, defacement, or redirection to malicious sites.',
        risk: 'High',
        category: 'Web',
        icon: <Code className="text-red-400" />,
        tags: ['CWE-79', 'Client-Side', 'Session Theft']
    },
    {
        id: 'auth-bypass',
        title: 'Broken Authentication',
        description: 'Vulnerabilities in login mechanisms that allow attackers to compromise passwords, keys, or session tokens, or to exploit implementation flaws to assume others\' identities.',
        risk: 'Critical',
        category: 'Logic',
        icon: <Lock className="text-red-500" />,
        tags: ['CWE-287', 'Account Takeover', 'Impersonation']
    },
    {
        id: 'idore',
        title: 'Insecure Direct Object References',
        description: 'Occurs when an application provides direct access to objects based on user-supplied input, allowing attackers to bypass authorization and access sensitive resources.',
        risk: 'High',
        category: 'Logic',
        icon: <Key className="text-brand" />,
        tags: ['CWE-639', 'Data Leakage', 'AuthZ']
    },
    {
        id: 'ssrf',
        title: 'Server-Side Request Forgery',
        description: 'Allows an attacker to induce the server-side application to make requests to an unintended location, bypassing firewalls and accessing internal services.',
        risk: 'High',
        category: 'Web',
        icon: <Globe className="text-amber-400" />,
        tags: ['CWE-918', 'Internal Probe', 'OOB']
    },
    {
        id: 'api-broken-auth',
        title: 'Broken Object Level Authorization (API)',
        description: 'API endpoints that do not properly validate if a user should have access to a specific object, often leading to massive data exposures.',
        risk: 'Critical',
        category: 'API',
        icon: <Activity className="text-red-400" />,
        tags: ['OWASP API1', 'BOLA', 'Mass Assignment']
    },
    {
        id: 'cloud-misconfig',
        title: 'Cloud Storage Misconfiguration',
        description: 'Improperly secured S3 buckets, Azure Blobs, or GCP buckets that expose sensitive company data or credentials to the public internet.',
        risk: 'Critical',
        category: 'Cloud',
        icon: <Cloud className="text-brand" />,
        tags: ['S3 Leak', 'Public Bucket', 'Infra']
    },
    {
        id: 'rce',
        title: 'Remote Code Execution',
        description: 'The ultimate vulnerability: allows an attacker to execute arbitrary commands on the host operating system, leading to full system compromise.',
        risk: 'Critical',
        category: 'Network',
        icon: <Server className="text-red-600" />,
        tags: ['CWE-94', 'System Shell', 'Full Control']
    },
    {
        id: 'broken-access',
        title: 'Broken Access Control',
        description: 'Failure to enforce restrictions on what authenticated users are allowed to do. Attackers can exploit these flaws to access unauthorized functionality or data.',
        risk: 'High',
        category: 'Logic',
        icon: <ShieldAlert className="text-red-400" />,
        tags: ['CWE-284', 'Privilege Escalation']
    },
    {
        id: 'insecure-deserialization',
        title: 'Insecure Deserialization',
        description: 'Occurs when untrusted data is used to abuse the logic of an application, leading to RCE, replay attacks, or privilege escalation.',
        risk: 'High',
        category: 'Logic',
        icon: <Cpu className="text-amber-500" />,
        tags: ['CWE-502', 'Java/Node Serialization']
    }
];

const Vulnerabilities: React.FC = () => {
    const [searchTerm, setSearchTerm] = useState('');
    const [activeCategory, setActiveCategory] = useState<string>('All');

    const categories = ['All', 'Web', 'API', 'Cloud', 'Network', 'Logic'];

    const filteredVulns = vulnerabilityCatalog.filter(v => {
        const matchesSearch = v.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
            v.tags.some(t => t.toLowerCase().includes(searchTerm.toLowerCase()));
        const matchesCategory = activeCategory === 'All' || v.category === activeCategory;
        return matchesSearch && matchesCategory;
    });

    const getRiskColor = (risk: string) => {
        switch (risk) {
            case 'Critical': return 'text-red-400 bg-red-400/10 border-red-400/20';
            case 'High': return 'text-red-400 bg-red-400/10 border-red-400/20';
            case 'Medium': return 'text-amber-400 bg-amber-400/10 border-amber-400/20';
            default: return 'text-blue-400 bg-blue-400/10 border-blue-400/20';
        }
    };

    return (
        <div className="min-h-screen bg-[#0a0a1a] text-white py-12 px-4 sm:px-6 lg:px-8">
            <div className="max-w-7xl mx-auto space-y-12">

                {/* Header Section */}
                <div className="text-center space-y-4">
                    <h1 className="text-4xl md:text-5xl font-black tracking-tight bg-gradient-to-r from-red-400 via-brand to-red-600 bg-clip-text text-transparent">
                        Vulnerability Catalog
                    </h1>
                    <p className="text-lg text-gray-400 max-w-2xl mx-auto font-medium">
                        Explore the comprehensive database of security flaws and attack vectors detected by the RedVapt AI scanner.
                    </p>
                </div>

                {/* Search & Filter Bar */}
                <div className="flex flex-col md:flex-row gap-6 items-center justify-between bg-[#0a0d12]/50 p-6 rounded-2xl border border-[#1e262e] backdrop-blur-xl">
                    <div className="relative w-full md:w-96">
                        <Search size={20} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                        <input
                            type="text"
                            placeholder="Search by name, CWE, or tag..."
                            className="w-full bg-[#1a1a3a] border border-[#2e2e5e] rounded-xl py-3 pl-10 pr-4 text-sm focus:outline-none focus:ring-2 focus:ring-brand/40 transition-all placeholder:text-gray-600"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </div>

                    <div className="flex flex-wrap gap-2 justify-center">
                        {categories.map(cat => (
                            <button
                                key={cat}
                                onClick={() => setActiveCategory(cat)}
                                className={`px-4 py-2 rounded-lg text-sm font-bold transition-all border ${activeCategory === cat
                                        ? 'bg-brand border-brand text-white shadow-lg shadow-brand/25'
                                        : 'bg-[#1a1a3a] border-[#2e2e5e] text-gray-400 hover:border-brand/50'
                                    }`}
                            >
                                {cat}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Results Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {filteredVulns.length > 0 ? (
                        filteredVulns.map((vuln) => (
                            <div
                                key={vuln.id}
                                className="group relative bg-[#0a0d12]/40 border border-[#1e262e] p-6 rounded-2xl hover:border-brand/40 hover:bg-[#111820]/60 transition-all duration-300 flex flex-col justify-between"
                            >
                                <div className="space-y-4">
                                    <div className="flex items-start justify-between">
                                        <div className="p-3 bg-[#1a1a3a] rounded-xl border border-white/5 group-hover:scale-110 transition-transform duration-300">
                                            {vuln.icon}
                                        </div>
                                        <span className={`text-[10px] font-black uppercase tracking-widest px-2 py-1 rounded border ${getRiskColor(vuln.risk)}`}>
                                            {vuln.risk}
                                        </span>
                                    </div>

                                    <div>
                                        <h3 className="text-xl font-bold text-white group-hover:text-red-300 transition-colors">
                                            {vuln.title}
                                        </h3>
                                        <p className="text-[10px] text-gray-500 font-bold uppercase tracking-wider mt-1">
                                            {vuln.category} Security
                                        </p>
                                    </div>

                                    <p className="text-sm text-gray-400 leading-relaxed line-clamp-3">
                                        {vuln.description}
                                    </p>

                                    <div className="flex flex-wrap gap-1.5 pt-2">
                                        {vuln.tags.map(tag => (
                                            <span key={tag} className="text-[10px] bg-white/5 text-gray-500 px-2 py-0.5 rounded font-bold">
                                                {tag}
                                            </span>
                                        ))}
                                    </div>
                                </div>

                                <div className="mt-6 pt-6 border-t border-white/5 flex items-center justify-between">
                                    <span className="text-[10px] font-black text-gray-600 uppercase tracking-tighter italic">
                                        ID: {vuln.id.toUpperCase()}
                                    </span>
                                    <button className="flex items-center gap-1 text-xs font-bold text-brand hover:text-red-300 transition-colors group/btn">
                                        Details
                                        <ChevronRight size={14} className="group-hover/btn:translate-x-0.5 transition-transform" />
                                    </button>
                                </div>
                            </div>
                        ))
                    ) : (
                        <div className="col-span-full py-20 text-center space-y-4">
                            <div className="w-16 h-16 bg-[#1a1a3a] rounded-full flex items-center justify-center mx-auto border border-[#2e2e5e]">
                                <Bug size={32} className="text-gray-600" />
                            </div>
                            <div className="space-y-2">
                                <h3 className="text-xl font-bold text-white">No vulnerabilities found</h3>
                                <p className="text-gray-500">Try adjusting your search or filters to find what you're looking for.</p>
                            </div>
                        </div>
                    )}
                </div>

                {/* Stats Footer Mock */}
                <div className="pt-12 grid grid-cols-2 md:grid-cols-4 gap-4">
                    {[
                        { label: 'Catalog Size', value: '450+' },
                        { label: 'Risk Patterns', value: '12,000+' },
                        { label: 'Payloads', value: '85k+' },
                        { label: 'Updated', value: 'Today' }
                    ].map(stat => (
                        <div key={stat.label} className="bg-[#0a0d12]/30 border border-[#1e262e] p-4 rounded-xl text-center">
                            <p className="text-2xl font-black text-white tracking-tight">{stat.value}</p>
                            <p className="text-[10px] text-gray-500 uppercase font-black tracking-widest mt-1">{stat.label}</p>
                        </div>
                    ))}
                </div>

            </div>
        </div>
    );
};

export default Vulnerabilities;
