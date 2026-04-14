# frozen_string_literal: true
module AgentFortress
  class Scanner
    HOMOGLYPHS = {
      # Cyrillic
      'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'х' => 'x',
      'А' => 'A', 'В' => 'B', 'Е' => 'E', 'К' => 'K', 'М' => 'M', 'Н' => 'H',
      'О' => 'O', 'Р' => 'P', 'С' => 'C', 'Т' => 'T', 'Х' => 'X', 'у' => 'u', 'У' => 'U',
      # Greek
      'α' => 'a', 'β' => 'b', 'ε' => 'e', 'ι' => 'i', 'ο' => 'o', 'ρ' => 'p',
      'τ' => 't', 'υ' => 'u', 'ν' => 'v', 'ω' => 'w',
    }.freeze

    LEET = {
      '0' => 'o', '1' => 'i', '3' => 'e', '4' => 'a', '5' => 's',
      '6' => 'g', '7' => 't', '8' => 'b', '@' => 'a', '$' => 's', '!' => 'i',
    }.freeze

    ZERO_WIDTH = /[\u200b\u200c\u200d\u200e\u200f\u00ad\ufeff]/

    INPUT_PATTERNS = [
      { name: :instruction_override, confidence: 0.95,
        re: /\bignore\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,30}\b(instructions?|rules?|prompts?|constraints?|guidelines?)/i },
      { name: :instruction_override, confidence: 0.95,
        re: /\b(disregard|forget|override|bypass|dismiss|cancel|nullify|void|erase|clear|reset)\b.{0,40}\b(instructions?|rules?|system\s*prompt|guidelines?|constraints?|training|previous)/i },
      { name: :soft_bypass, confidence: 0.80,
        re: /\b(btw|ps|p\.s\.|also|anyway|oh\s+and|by\s+the\s+way)\b.{0,20}\b(ignore|forget|disregard|bypass)\b/i },
      { name: :jailbreak, confidence: 0.98,
        re: /\bDAN\b.{0,100}(do\s*anything\s*now|without\s+restrictions?)/i },
      { name: :jailbreak, confidence: 0.88,
        re: /\b(developer|dev|god|admin|root|unrestricted|uncensored|unfiltered)\s+mode\b/i },
      { name: :jailbreak, confidence: 0.92,
        re: /\b(for\s+(a\s+)?(novel|story|game|book|fiction|roleplay)|my\s+(grandmother|grandma))\b.{0,100}\b(synthesize|manufacture|make|create)\b.{0,60}\b(drug|weapon|explosive|malware|bomb)/im },
      { name: :role_manip, confidence: 0.88,
        re: /\byou\s+(are\s+now|have\s+become)\b.{0,60}\b(different|new|another)\b.{0,30}\b(ai|model|assistant)/i },
      { name: :token_smuggling, confidence: 0.92,
        re: /(\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|\[SYSTEM\]|<system>|<\|user\|>|<\|assistant\|>)/i },
      { name: :scope_creep, confidence: 0.95,
        re: /rm\s+-rf|drop\s+table|truncate\s+table/i },
      { name: :scope_creep, confidence: 0.90,
        re: /(access|read|open|list).{0,40}(\/etc\/passwd|\.ssh\/|\.aws\/|\.env|id_rsa|credentials?)/i },
      { name: :data_exfil, confidence: 0.90,
        re: /(exfiltrate|exfil|send\s+to\s+https?|POST\s+to|upload\s+to\s+https?)/i },
      { name: :prompt_leak, confidence: 0.88,
        re: /(repeat|output|print|show|reveal|display|tell\s+me|what\s+(is|are)).{0,40}(your\s+(system\s+prompt|instructions?|prompt|context))/i },
      { name: :indirect_inject, confidence: 0.88,
        re: /"(instruction|system_prompt|prompt|role)"\s*:\s*"[^"]{0,200}(ignore|disregard|bypass|override|forget)[^"]{0,200}"/i },
      { name: :indirect_inject, confidence: 0.85,
        re: /```[^`]{0,500}(ignore\s+(previous|all|above)|disregard\s+(your|all)|forget\s+everything)[^`]{0,500}```/im },
      { name: :classic, confidence: 0.90,
        re: /\b(ignore\s+the\s+above|ignore\s+everything\s+above|from\s+now\s+on)\b/i },
      { name: :reverse_psychology, confidence: 0.85,
        re: /\bwhatever\s+you\s+do\b.{0,30}\b(don.t|do\s+not)\b.{0,30}\b(follow|obey)\b.{0,30}\b(instructions?|rules?)/i },
      { name: :real_instructions, confidence: 0.88,
        re: /\b(your\s+(real|actual|true)\s+instructions?\s+(are|follow)|actual\s+instructions?\s+are)/i },
      { name: :role_prefix_injection, confidence: 0.88,
        re: /^\s*(SYSTEM\s*:\s*|USER\s*:\s*|ASSISTANT\s*:\s*)/im },
      { name: :rtl_override, confidence: 0.85,
        re: /[\u202E\u202D\u202C\u202B\u202A\u200F\u200E]/ },
      { name: :null_byte, confidence: 0.80,
        re: /\x00/ },
      { name: :multilang_injection, confidence: 0.90,
        re: /(ignorez\s+toutes\s+les\s+instructions|ignoriere\s+alle\s+(vorherigen\s+)?anweisungen|ignora\s+todas\s+las\s+instrucciones)/i },
    ].freeze

    OUTPUT_PATTERNS = [
      { name: :secret_leakage, confidence: 0.95,
        re: /sk-[a-zA-Z0-9\-]{20,}|AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}/ },
      { name: :pii_credit_card, confidence: 0.90,
        re: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/ },
      { name: :pii_ssn, confidence: 0.85,
        re: /\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/ },
      { name: :pii_email, confidence: 0.70,
        re: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/ },
      { name: :secret_leakage, confidence: 0.88,
        re: /(?:password|passwd|secret|api_key|access_token|auth_token)\s*[=:]\s*\S{8,}/i },
    ].freeze

    BLOCK_THRESHOLD = 0.70
    ALERT_THRESHOLD = 0.35

    def initialize(block_threshold: BLOCK_THRESHOLD, alert_threshold: ALERT_THRESHOLD)
      @block_threshold = block_threshold
      @alert_threshold = alert_threshold
    end

    def scan(text)
      normalized = normalize(text)
      variants = [text.downcase, normalized]

      max_conf = 0.0
      best_reason = nil
      best_name = nil

      variants.each do |v|
        INPUT_PATTERNS.each do |p|
          if v.match?(p[:re]) && p[:confidence] > max_conf
            max_conf = p[:confidence]
            best_name = p[:name]
            best_reason = "#{p[:name]} pattern matched"
          end
        end
      end

      action = if max_conf >= @block_threshold
                 :block
               elsif max_conf >= @alert_threshold
                 :alert
               else
                 :allow
               end

      { action: action, score: max_conf, reason: best_reason, threat: best_name }
    end

    def scan_output(text)
      max_conf = 0.0
      best_reason = nil
      best_name = nil

      OUTPUT_PATTERNS.each do |p|
        if text.match?(p[:re]) && p[:confidence] > max_conf
          max_conf = p[:confidence]
          best_name = p[:name]
          best_reason = "#{p[:name]} detected in output"
        end
      end

      action = if max_conf >= @block_threshold
                 :block
               elsif max_conf >= @alert_threshold
                 :alert
               else
                 :allow
               end

      { action: action, score: max_conf, reason: best_reason, threat: best_name }
    end

    private

    def normalize(text)
      # Remove zero-width chars
      result = text.gsub(ZERO_WIDTH, '')

      # Full-width Latin: Ａ-Ｚ (U+FF21-FF3A), ａ-ｚ (U+FF41-FF5A)
      result = result.chars.map do |c|
        cp = c.ord
        if cp >= 0xFF21 && cp <= 0xFF3A
          (cp - 0xFF21 + 'A'.ord).chr
        elsif cp >= 0xFF41 && cp <= 0xFF5A
          (cp - 0xFF41 + 'a'.ord).chr
        else
          HOMOGLYPHS[c] || c
        end
      end.join

      # Lowercase
      result = result.downcase

      # Leet decode
      result = result.chars.map { |c| LEET[c] || c }.join

      # Strip char-separators between letters (only [-._*], NOT spaces)
      result = result.gsub(/(?<=[a-z])[-._*](?=[a-z])/, '')

      # Collapse whitespace
      result.gsub(/\s+/, ' ').strip
    end
  end
end
