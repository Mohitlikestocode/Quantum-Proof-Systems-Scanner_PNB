import { useRef, useState } from 'react';

const AIAssistant = () => {
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const [showToast, setShowToast] = useState(false);
  const [toastMsg, setToastMsg] = useState("");
  const [showActiveContext, setShowActiveContext] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8000';
  const inFlightRef = useRef(false);
  const lastSubmissionRef = useRef<{ message: string; ts: number } | null>(null);
  const [messages, setMessages] = useState<any[]>([
    {
      role: 'ai',
      text: "Greetings, Administrator. I am your Precise Sentinel AI. I can help you orchestrate scans, analyze cryptographic vulnerabilities, or automate reporting across your quantum-vulnerable infrastructure.\n\nWhat would you like to execute today?"
    }
  ]);

  const handleSend = async (manualInput?: string) => {
    const userMsg = (manualInput || input).trim();
    if (!userMsg) return;

    // Guard against accidental double-submit from rapid key/mouse actions.
    if (inFlightRef.current) return;
    const now = Date.now();
    if (
      lastSubmissionRef.current &&
      lastSubmissionRef.current.message === userMsg &&
      now - lastSubmissionRef.current.ts < 1200
    ) {
      return;
    }

    inFlightRef.current = true;
    lastSubmissionRef.current = { message: userMsg, ts: now };

    setInput("");
    setMessages(prev => [...prev, { role: 'user', text: userMsg }]);
    setIsTyping(true);

    try {
      const res = await fetch(apiBase + '/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userMsg })
      });
      const contentType = res.headers.get('content-type') || '';
      let data: any = {};

      if (contentType.includes('application/json')) {
        data = await res.json();
      } else {
        const rawText = await res.text();
        data = { detail: rawText || 'Unexpected response from AI service.' };
      }

      if (!res.ok) {
        throw new Error(data?.detail || data?.message || `AI service request failed with status ${res.status}`);
      }

      const assistantText = data?.response || data?.explanation || 'Command received.';
      
      setMessages(prev => [...prev, {
        role: 'system',
        action: data.action,
        text: assistantText,
        data: data.data
      }]);

      // Show toast if there's an action
      if (data.action !== "none" && data.action !== "CHAT") {
         let actionStr = `Command Executed: ${data.action.toUpperCase()}`;
         if (data.action === "SCHEDULE_SCAN") actionStr = "Scan Successfully Scheduled";
         if (data.action === "SHOW_VULNERABLE") actionStr = "Vulnerability Report Generated";
         if (data.action === "EMAIL_REPORT") actionStr = "PDF Report Emailed Successfully";
         if (data.action === "SCAN_TARGET") actionStr = "Target Analysis Completed";
         
         setToastMsg(actionStr);
         setShowToast(true);
         setTimeout(() => setShowToast(false), 4000);
      }

    } catch (err: any) {
      console.error("Chat failed", err);
      const errorMessage = err?.message || 'Unable to reach AI service. Ensure backend is running on port 8010.';
      setMessages(prev => [...prev, { role: 'error', text: `AI request failed: ${errorMessage}` }]);
      setToastMsg(`Action Failed: ${errorMessage}`);
      setShowToast(true);
      setTimeout(() => setShowToast(false), 4000);
    } finally {
      inFlightRef.current = false;
      setIsTyping(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      handleSend();
    }
  };

  return (
    <div className="flex-1">
      <main className="md:ml-64 pt-24 pb-8 px-8 min-h-screen bg-background relative">
        <div className="max-w-5xl mx-auto h-[calc(100vh-140px)] flex flex-col gap-6">
          {/* Page Header */}
          <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 md:gap-0">
            <div>
              <h2 className="text-3xl font-extrabold tracking-tight text-on-surface">AI Command Center</h2>
              <p className="text-on-surface-variant text-sm mt-1">Intelligent automation and cryptographic guidance</p>
            </div>
            <div className="flex gap-2">
              <div className="bg-surface-container-lowest px-4 py-2 rounded-lg shadow-sm flex items-center gap-2 border border-outline-variant/10">
                <span className="text-xs font-bold text-on-surface-variant">ENGINE:</span>
                <span className="text-xs font-bold text-primary">QUANTUM-GPT-4</span>
              </div>
            </div>
          </div>

          {/* Chat Interface Bento */}
          <div className="flex-1 grid grid-cols-1 md:grid-cols-12 gap-4 sm:gap-6 min-h-0">
            {/* History & Settings Panel */}
            <div className="col-span-3 flex flex-col gap-4">
              <div className="bg-surface-container-low rounded-xl p-4 flex-1 flex flex-col overflow-hidden">
                <p className="text-[10px] font-bold text-on-surface-variant tracking-widest uppercase mb-4">Recent Conversations</p>
                <div className="space-y-3 overflow-y-auto pr-2">
                  <button onClick={() => handleSend("Summarize transition plan for TLS 1.3 migration")}
                    className="w-full text-left p-3 bg-surface-container-lowest rounded-lg border-l-4 border-primary shadow-sm cursor-pointer">
                    <p className="text-xs font-bold truncate">TLS 1.3 Transition Plan</p>
                    <p className="text-[10px] text-on-surface-variant mt-1">2 mins ago</p>
                  </button>
                  <button onClick={() => handleSend("Explain symmetric key rotation best practices")}
                    className="w-full text-left p-3 hover:bg-surface-container-highest/50 rounded-lg cursor-pointer transition-colors">
                    <p className="text-xs font-medium text-on-surface-variant truncate">Symmetric Key Rotation</p>
                    <p className="text-[10px] text-on-surface-variant/60 mt-1">1 hour ago</p>
                  </button>
                  <button onClick={() => handleSend("Run a NIST compliance audit summary for latest scans")}
                    className="w-full text-left p-3 hover:bg-surface-container-highest/50 rounded-lg cursor-pointer transition-colors">
                    <p className="text-xs font-medium text-on-surface-variant truncate">NIST Compliance Audit</p>
                    <p className="text-[10px] text-on-surface-variant/60 mt-1">Yesterday</p>
                  </button>
                </div>
              </div>
              
              {/* Suggested Actions Bento Block */}
              <div className="bg-surface-container-highest rounded-xl p-4">
                <p className="text-[10px] font-bold text-on-surface-variant tracking-widest uppercase mb-3">Quick Commands</p>
                <div className="grid grid-cols-1 gap-2">
                  <button onClick={() => handleSend("Scan pnb.com")} className="text-left px-3 py-2 bg-white/50 hover:bg-white text-[11px] font-medium rounded-lg border border-outline-variant/10 transition-all flex items-center justify-between group">
                    <span>Scan pnb.com</span>
                    <span className="material-symbols-outlined text-[14px] text-primary opacity-0 group-hover:opacity-100 transition-opacity">rocket_launch</span>
                  </button>
                  <button onClick={() => handleSend("Email the risk report to ceo@bank.com")} className="text-left px-3 py-2 bg-white/50 hover:bg-white text-[11px] font-medium rounded-lg border border-outline-variant/10 transition-all flex items-center justify-between group">
                    <span>Email the risk report to ceo@bank.com</span>
                    <span className="material-symbols-outlined text-[14px] text-primary opacity-0 group-hover:opacity-100 transition-opacity">description</span>
                  </button>
                  <button onClick={() => handleSend("Schedule check for internal.com every week at 3 PM")} className="text-left px-3 py-2 bg-white/50 hover:bg-white text-[11px] font-medium rounded-lg border border-outline-variant/10 transition-all flex items-center justify-between group">
                    <span className="truncate mr-2">Schedule check for internal.com every week at 3 PM</span>
                    <span className="material-symbols-outlined text-[14px] text-primary opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0">event_repeat</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Conversational Canvas */}
            <div className="col-span-9 flex flex-col bg-surface-container-lowest rounded-2xl shadow-sm border border-outline-variant/5 overflow-hidden">
              {/* Chat Scroll Area */}
              <div className="flex-1 overflow-y-auto p-8 space-y-8">
                {messages.map((msg, i) => (
                  <div key={i}>
                    {msg.role === 'ai' && (
                      <div className="flex gap-4 max-w-3xl">
                        <div className="w-10 h-10 rounded-lg bg-primary-container flex-shrink-0 flex items-center justify-center text-white">
                          <span className="material-symbols-outlined text-xl" style={{ fontVariationSettings: "'FILL' 1" }}>smart_toy</span>
                        </div>
                        <div className="space-y-4">
                          <div className="bg-surface-container-low p-5 rounded-2xl rounded-tl-none">
                            <p className="text-sm leading-relaxed text-on-surface whitespace-pre-wrap">
                              {msg.text}
                            </p>
                          </div>
                          {i === 0 && (
                            <div className="flex flex-wrap gap-2">
                              <button onClick={() => handleSend("Explain TLS 1.0 vulnerability")} className="px-3 py-1.5 rounded-full border border-primary/20 bg-primary/5 text-primary text-[11px] font-bold hover:bg-primary/10 transition-colors">
                                "Explain TLS 1.0 vulnerability"
                              </button>
                              <button onClick={() => handleSend("Show high risk assets")} className="px-3 py-1.5 rounded-full border border-primary/20 bg-primary/5 text-primary text-[11px] font-bold hover:bg-primary/10 transition-colors">
                                "Show high risk assets"
                              </button>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {msg.role === 'user' && (
                      <div className="flex gap-4 max-w-3xl ml-auto flex-row-reverse">
                        <div className="w-10 h-10 rounded-lg bg-surface-container-highest flex-shrink-0 flex items-center justify-center">
                          <span className="material-symbols-outlined text-xl text-on-surface-variant">person</span>
                        </div>
                        <div className="bg-primary text-white p-4 rounded-2xl rounded-tr-none shadow-md shadow-primary/20">
                          <p className="text-sm font-medium">{msg.text}</p>
                        </div>
                      </div>
                    )}

                    {msg.role === 'system' && (
                      <div className="flex gap-4 max-w-3xl">
                        <div className="w-10 h-10 rounded-lg bg-primary-container flex-shrink-0 flex items-center justify-center text-white">
                          <span className="material-symbols-outlined text-xl" style={{ fontVariationSettings: "'FILL' 1" }}>smart_toy</span>
                        </div>
                        <div className="flex-1 space-y-4">
                          <div className="bg-surface-container-low p-5 rounded-2xl rounded-tl-none border border-primary/10">
                            <p className="text-sm font-bold text-primary flex items-center gap-2 mb-4">
                              <span className="material-symbols-outlined text-sm">settings_suggest</span>
                              EXECUTING COMMAND CHAIN...
                            </p>
                            <div className="space-y-3">
                              <div className="flex items-center justify-between p-3 bg-white rounded-lg border border-tertiary/20">
                                <div className="flex items-center gap-3">
                                  <div className="w-6 h-6 rounded-full bg-tertiary flex items-center justify-center">
                                    <span className="material-symbols-outlined text-[14px] text-white">check</span>
                                  </div>
                                  <span className="text-xs font-semibold text-on-surface">{msg.text || msg.action || 'Command completed.'}</span>
                                </div>
                                <span className="text-[10px] font-bold text-tertiary">
                                  {msg.action === "SCHEDULE_SCAN" ? "SCHEDULED" : msg.action === "EMAIL_REPORT" ? "SENT" : "SUCCESS"}
                                </span>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    {msg.role === 'error' && (
                      <div className="flex gap-4 max-w-3xl">
                        <div className="w-10 h-10 rounded-lg bg-error/90 flex-shrink-0 flex items-center justify-center text-white">
                          <span className="material-symbols-outlined text-xl" style={{ fontVariationSettings: "'FILL' 1" }}>error</span>
                        </div>
                        <div className="bg-error/10 border border-error/30 p-5 rounded-2xl rounded-tl-none">
                          <p className="text-sm font-semibold text-error">{msg.text}</p>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
                
                {isTyping && (
                  <div className="flex gap-4 max-w-3xl">
                    <div className="w-10 h-10 rounded-lg bg-primary-container flex-shrink-0 flex items-center justify-center text-white">
                      <span className="material-symbols-outlined text-xl" style={{ fontVariationSettings: "'FILL' 1" }}>smart_toy</span>
                    </div>
                    <div className="bg-surface-container-low p-5 rounded-2xl rounded-tl-none flex items-center gap-2">
                       <span className="w-2 h-2 rounded-full bg-primary animate-bounce"></span>
                       <span className="w-2 h-2 rounded-full bg-primary animate-bounce delay-150"></span>
                       <span className="w-2 h-2 rounded-full bg-primary animate-bounce delay-300"></span>
                    </div>
                  </div>
                )}
              </div>

              {/* Input Area */}
              <div className="p-6 bg-surface-container-low border-t border-outline-variant/10">
                <div className="bg-surface-container-lowest rounded-xl border border-outline-variant/30 p-2 focus-within:ring-2 ring-primary/20 transition-all flex items-end gap-3 shadow-inner">
                  <button onClick={() => fileInputRef.current?.click()} className="p-2 hover:bg-surface-container-low rounded-lg transition-colors text-on-surface-variant w-full sm:w-auto" title="Attach a file reference">
                    <span className="material-symbols-outlined">attach_file</span>
                  </button>
                  <input
                    ref={fileInputRef}
                    type="file"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (!file) return;
                      handleSend(`Analyze attachment context for file: ${file.name}`);
                      e.target.value = '';
                    }}
                  />
                  <textarea 
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    disabled={isTyping}
                    className="flex-1 bg-transparent border-none focus:ring-0 text-sm font-medium py-2 resize-none max-h-32 min-h-[40px] text-on-surface" 
                    placeholder="Type a command (e.g., 'Schedule a full CBOM audit for next Monday at 9AM')..."
                  ></textarea>
                  <button 
                    onClick={() => handleSend()}
                    disabled={isTyping || !input.trim()}
                    className="bg-primary text-white h-10 w-10 rounded-lg flex items-center justify-center hover:bg-primary-container active:scale-95 transition-all shadow-md shadow-primary/20 disabled:opacity-50"
                  >
                    <span className="material-symbols-outlined">arrow_upward</span>
                  </button>
                </div>
                <div className="flex justify-between items-center mt-3 px-1">
                  <div className="flex flex-col sm:flex-row gap-4">
                    <button onClick={() => setMessages([{ role: 'ai', text: "Greetings, Administrator. I am your Precise Sentinel AI. I can help you orchestrate scans, analyze cryptographic vulnerabilities, or automate reporting across your quantum-vulnerable infrastructure.\n\nWhat would you like to execute today?" }])} className="flex items-center gap-1.5 text-[10px] font-bold text-on-surface-variant cursor-pointer hover:text-primary transition-colors">
                      <span className="material-symbols-outlined text-[14px]">history</span>
                      RESTORE SESSION
                    </button>
                    <button onClick={() => window.open((import.meta.env.VITE_API_URL || 'http://localhost:8000') + '/docs', '_blank')} className="flex items-center gap-1.5 text-[10px] font-bold text-on-surface-variant cursor-pointer hover:text-primary transition-colors">
                      <span className="material-symbols-outlined text-[14px]">auto_fix</span>
                      MODEL SETTINGS
                    </button>
                  </div>
                  <p className="text-[10px] text-on-surface-variant/60 font-medium">Press Ctrl/Cmd + Enter to send</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Contextual Info Hover Button and Tooltip */}
        <div className="fixed top-24 right-8 z-50">
          <button 
            onClick={() => setShowActiveContext(!showActiveContext)}
            className={`w-10 h-10 rounded-full glass-panel shadow-lg border border-primary/20 flex items-center justify-center transition-colors ${showActiveContext ? 'bg-primary/20 text-primary' : 'text-primary hover:bg-primary/10'}`}
          >
            <span className="material-symbols-outlined text-xl">{showActiveContext ? 'close' : 'info'}</span>
          </button>
          
          <div className={`absolute top-12 right-0 w-72 glass-panel rounded-xl shadow-2xl border border-white/40 border-t-4 border-t-primary p-4 transition-all duration-300 ${showActiveContext ? 'opacity-100 translate-y-0' : 'opacity-0 pointer-events-none translate-y-2'}`}>
            <div className="flex items-start justify-between mb-3">
              <span className="text-[10px] font-extrabold tracking-widest text-primary uppercase">Active Intelligence</span>
              <span className="w-2 h-2 rounded-full bg-tertiary animate-pulse"></span>
            </div>
            <p className="text-xs font-bold text-on-surface mb-2">PQC Discovery Engine</p>
            <p className="text-[11px] leading-relaxed text-on-surface-variant">
              The assistant is currently cross-referencing your <span className="font-bold text-on-surface">Kyber-768</span> implementation against the latest NIST draft standards.
            </p>
            <div className="mt-4 pt-3 border-t border-outline-variant/20">
              <div className="w-full bg-surface-container-highest h-1 rounded-full overflow-hidden">
                <div className="bg-primary h-full w-3/4 rounded-full"></div>
              </div>
              <p className="text-[9px] text-on-surface-variant mt-2 font-medium">75% Context Synchronization Complete</p>
            </div>
          </div>
        </div>
      </main>

      {/* Toast Notification */}
      {showToast && (
        <div className="fixed bottom-8 right-[320px] bg-surface-container-highest text-on-surface px-6 py-4 rounded-xl shadow-2xl flex items-center gap-4 z-50 animate-in fade-in slide-in-from-bottom-8">
          <span className="material-symbols-outlined text-primary">check_circle</span>
          <p className="text-sm font-bold">{toastMsg}</p>
        </div>
      )}
    </div>
  );
};

export default AIAssistant;

