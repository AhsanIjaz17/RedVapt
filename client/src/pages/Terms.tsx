import React from 'react';
import { Gavel, Scale, AlertOctagon, CheckCircle2 } from 'lucide-react';

const Terms: React.FC = () => {
    return (
        <div className="min-h-screen bg-slate-950 text-slate-300 pt-32 pb-20 px-6">
            <div className="max-w-4xl mx-auto">
                <div className="mb-16 text-center">
                    <div className="inline-flex items-center justify-center p-3 bg-brand/10 border border-brand/20 rounded-2xl mb-6">
                        <Gavel className="w-8 h-8 text-brand" />
                    </div>
                    <h1 className="text-4xl md:text-5xl font-black text-white mb-6 tracking-tight">
                        Terms of <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-400 to-brand">Service</span>
                    </h1>
                    <p className="text-lg text-slate-400 max-w-2xl mx-auto font-medium">
                        Please read these terms carefully before using the RedVapt platform. Use of our service implies acceptance of these guidelines.
                    </p>
                </div>

                <div className="grid gap-8">
                    <div className="bg-slate-900/50 border border-slate-800 rounded-3xl p-8 md:p-10">
                        <div className="flex items-center gap-4 mb-6">
                            <Scale className="w-6 h-6 text-red-400" />
                            <h2 className="text-2xl font-bold text-white">Acceptable Use</h2>
                        </div>
                        <div className="space-y-4">
                            <p className="text-slate-400 leading-relaxed">
                                RedVapt is a professional security testing tool. By using this service, you agree to:
                            </p>
                            <ul className="space-y-3">
                                {[
                                    "Only scan targets for which you have explicit, written authorization.",
                                    "Comply with all local, state, and international cybersecurity laws.",
                                    "Not use the platform for malicious activities or unauthorized intrusions.",
                                    "Maintain the confidentiality of all scan results and findings."
                                ].map((item) => (
                                    <li key={item} className="flex items-start gap-3 text-sm">
                                        <CheckCircle2 className="w-5 h-5 text-brand mt-0.5 shrink-0" />
                                        <span>{item}</span>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    </div>

                    <div className="bg-slate-900/50 border border-slate-800 rounded-3xl p-8 md:p-10 border-l-4 border-l-red-500/30">
                        <div className="flex items-center gap-4 mb-6">
                            <AlertOctagon className="w-6 h-6 text-red-400" />
                            <h2 className="text-2xl font-bold text-white">Liability Disclaimer</h2>
                        </div>
                        <p className="text-slate-400 leading-relaxed italic">
                            RedVapt provides security assessments on an "as-is" basis. We are not liable for any damages, data loss, or service interruptions that may occur during the testing process. Penetration testing inherently carries risks to target systems; ensure all critical data is backed up before initiating scans.
                        </p>
                    </div>

                    <div className="grid md:grid-cols-2 gap-8">
                        <div className="bg-slate-900/50 border border-slate-800 rounded-3xl p-8">
                            <h3 className="text-xl font-bold text-white mb-4">Account Responsibilities</h3>
                            <p className="text-sm text-slate-400 leading-relaxed">
                                You are responsible for maintaining the security of your account credentials (email and password) and for all activities that occur under your workspace.
                            </p>
                        </div>
                        <div className="bg-slate-900/50 border border-slate-800 rounded-3xl p-8">
                            <h3 className="text-xl font-bold text-white mb-4">Service Access</h3>
                            <p className="text-sm text-slate-400 leading-relaxed">
                                We reserve the right to suspend or terminate access to the platform for any user who violates these terms or engages in unethical behavior.
                            </p>
                        </div>
                    </div>

                    <div className="pt-12 border-t border-slate-800 text-center">
                        <p className="text-slate-500 text-sm italic">
                            Last updated: April 25, 2026. These terms constitute a legally binding agreement between you and the RedVapt Ecosystem.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Terms;
