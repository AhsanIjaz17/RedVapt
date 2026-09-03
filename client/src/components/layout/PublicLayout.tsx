
import React from 'react';
import Navbar from './Navbar';
import Footer from './Footer';

interface PublicLayoutProps {
    children: React.ReactNode;
}

const PublicLayout: React.FC<PublicLayoutProps> = ({ children }) => {
    return (
        <div className="min-h-screen flex flex-col bg-[#020617] text-slate-100 selection:bg-brand/30">
            <Navbar />
            <main className="flex-1">
                {children}
            </main>
            <Footer />

            {/* Background Gradients */}
            <div className="fixed top-0 left-0 w-full h-full -z-50 pointer-events-none overflow-hidden">
                <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-brand/10 blur-[120px] rounded-full"></div>
                <div className="absolute bottom-[0%] right-[-5%] w-[35%] h-[35%] bg-red-700/12 blur-[100px] rounded-full"></div>
            </div>
        </div>
    );
};

export default PublicLayout;
