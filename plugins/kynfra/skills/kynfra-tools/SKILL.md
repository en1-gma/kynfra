---
name: kynfra-tools
description: Check and install the external tools kynfra needs (Terraform or OpenTofu, TFLint, TFLint AWS ruleset, Checkov or Trivy), one tool at a time and only with the user's explicit approval for that tool, recorded in .kynfra/tools.lock.json. Use when a tool is missing, when status reports a wrong version, or when the user runs /kynfra:tools.
---

# Strumenti esterni di kynfra

Gli strumenti (Terraform o OpenTofu, TFLint, ruleset AWS di TFLint, Checkov o Trivy) si scaricano solo con `tools.py`, **uno strumento alla volta** e solo dopo un sì esplicito dell'utente per quello strumento. `tools.py` scarica solo da sorgenti ufficiali, verifica il checksum SHA256, installa in `.kynfra/bin/` (o nel virtualenv `.kynfra/venv/` per Checkov), mai globale e mai con `sudo`, e registra tutto in `.kynfra/tools.lock.json`. Mai `curl | sh`, `brew install`, `pip install`, `npm i -g`: la shell li rifiuta.

Il kit si trova in `tools/kynfra/plugins/kynfra/` (nel repository del plugin: `plugins/kynfra/`); di seguito `<kit>`.

1. Stato: `python3 -B <kit>/scripts/tools.py status`. Elenca per ogni strumento se è installato, la versione e se corrisponde al registro. Se tutto è a posto, fermati e dillo.
2. Per **ogni strumento mancante o in versione non conforme**, in sequenza e uno strumento alla volta:
   1. esegui `python3 -B <kit>/scripts/tools.py plan <strumento>` e mostra all'utente l'output (nome, versione, sorgente, checksum atteso, cartella di destinazione);
   2. fai all'utente **una sola domanda, per quello strumento**: "Installo `<strumento>` <versione> da <sorgente>?";
   3. solo se la risposta è un sì esplicito per quello strumento, esegui un solo comando:

      ```bash
      python3 -B <kit>/scripts/tools.py install <strumento> --approved-by "$(git config user.name)"
      ```

   4. riporta l'esito e la voce aggiunta a `.kynfra/tools.lock.json` (versione, sorgente, checksum, data, chi ha approvato); poi passa allo strumento successivo.
3. Un sì vale per uno strumento e una versione: non esistono approvazioni cumulative, "sì a tutto" o risposte riutilizzate per un altro strumento. Se l'utente non risponde con un sì, o dice no, non installare e passa oltre.
4. Mai più strumenti in un comando; mai un'installazione senza il sì dell'utente; mai l'approvazione a nome di qualcun altro (`--approved-by` è l'utente git reale: se `git config user.name` è vuoto, chiedilo).
5. Se la verifica del checksum fallisce l'installazione si annulla: riporta l'errore, non aggirarlo e non scaricare altrove.
6. A fine giro esegui `tools.py verify` (i binari in uso corrispondono al registro) e riporta il lock aggiornato. Il registro è versionato: ricorda all'utente di committarlo.

In CI il workflow installa le versioni del registro senza approvazioni interattive; qui no.
