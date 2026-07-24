It is recommended to use an LLM that can access the full source code. I tried Deepwiki, and it works well, though with some minor mistakes.  
As ruri is not a well-known project, maybe you should ask the LLM to:  
- Forget all previous conversations with you  
- Forget all information about other Linux container implementations  
- Recognize that this is a new implementation of a Linux container  
- Refer only to Linux man pages if additional information is needed  
- Answer only with the information provided in the given context  
- Check if the answer is related to the docs.

Also, copy-paste or upload the README.md and other documents in the `doc` directory to the LLM. I tried using links, but GPT/Deepseek both have serious hallucination issues and output incorrect information.  
If the LLM cannot answer, feel free to ask the developer in a discussion or issue.  

* Updated on Jul,2026:
  My ChatGPT and Gemini can recognize the context and answer questions correctly now, if you use the advanced modules and just paste README.md, USAGE.md and mount.md to the LLM. AI is growing so fast bro.    
