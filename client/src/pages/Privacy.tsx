import React from 'react';
import { Shield, Lock, Eye, FileText } from 'lucide-react';

const Privacy: React.FC = () => {
    return (
        <div className="min-h-screen bg-slate-950 text-slate-300 pt-32 pb-20 px-6">
            <div className="max-w-4xl mx-auto">
                <div className="mb-16 text-center">
                    <div className="inline-flex items-center justify-center p-3 bg-brand/10 border border-brand/20 rounded-2xl mb-6">
                        <Shield className="w-8 h-8 text-brand" />
                    </div>
                    <h1 className="text-4xl md:text-5xl font-black text-white mb-6 tracking-tight">
                        Privacy <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-400 to-brand">Policy</span>
                    </h1>
                    <p className="text-lg text-slate-400 max-w-2xl mx-auto font-medium">
                        At RedVapt, we take your security and privacy seriously. This policy outlines how we handle your data and ensure your information remains protected.
                    </p>
                </div>

                <div className="space-y-12">
                    <section className="bg-slate-900/50 border border-slate-800 rounded-3xl p-8 md:p-10">
                        <div className="flex items-start gap-5 mb-6">
                            <div className="p-2.5 bg-brand/10 border border-brand/20 rounded-xl">
                                <Eye className="w-6 h-6 text-red-400" />
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold text-white mb-2">Information We Collect</h2>
                                <p className="text-slate-400 leading-relaxed">
                                    We collect information necessary to provide our security scanning services, including account details, target URLs, and scan results. Your information is kept secure and used only for the purposes outlined in this policy.
                                </p>
                            </div>
                        </div>
                    </section>

                    <section className="bg-slate-900/50 border border-slate-800 rounded-3xl p-8 md:p-10">
                        <div className="flex items-start gap-5 mb-6">
                            <div className="p-2.5 bg-brand/10 border border-brand/20 rounded-xl">
                                <Lock className="w-6 h-6 text-brand" />
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold text-white mb-2">How We Use Your Data</h2>
                                <p className="text-slate-400 leading-relaxed">
                                    Your data is used exclusively for performing vulnerability assessments and generating reports. We do not sell, trade, or otherwise transfer your personally identifiable information to outside parties. All scan data is encrypted at rest and in transit.
                                </p>
                            </div>
                        </div>
                    </section>

                    <div className="grid md:grid-cols-2 gap-8">
                        <div className="bg-slate-900/50 border border-slate-800 rounded-3xl p-8">
                            <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-3">
                                <FileText className="w-5 h-5 text-brand" />
                                Data Retention
                            </h3>
                            <p className="text-sm text-slate-400 leading-relaxed">
                                Scan logs and reports are retained as long as your workspace is active. You can request data deletion at any time through your dashboard settings.
                            </p>
                        </div>
                        <div className="bg-slate-900/50 border border-slate-800 rounded-3xl p-8">
                            <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-3">
                                <Shield className="w-5 h-5 text-red-400" />
                                Security Standards
                            </h3>
                            <p className="text-sm text-slate-400 leading-relaxed">
                                We employ industry-standard security measures to protect your information, including multi-factor authentication and strict access controls for all internal services.
                            </p>
                        </div>
                    </div>

                    <div className="pt-12 border-t border-slate-800 text-center">
                        <p className="text-slate-500 text-sm italic">
                            Last updated: April 25, 2026. For questions regarding this policy, contact the RedVapt Security Team.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Privacy;
