# test_model.py
from ultralytics import YOLO
import os
import numpy as np

# --- CONFIGURAÇÕES ---
MODEL_PATH = os.path.join('app', 'models', 'best.pt')
IMAGE_PATH = r"C:\Users\Lucas\OneDrive\Área de Trabalho\Ic_processamento_img\TreinamentoCNN\img\Imagem do WhatsApp de 2025-09-17 à(s) 10.42.50_5916d4bb.jpg"
PIXEL_POR_MM = 16.4  # Ajuste este valor conforme sua calibração
# --------------------

if not os.path.exists(MODEL_PATH):
    print(f"ERRO: Modelo não encontrado em '{MODEL_PATH}'")
elif not os.path.exists(IMAGE_PATH):
    print(f"ERRO: Imagem não encontrada em '{IMAGE_PATH}'")
else:
    print("Arquivos encontrados. Carregando o modelo...")
    try:
        model = YOLO(MODEL_PATH)
        print("Modelo carregado com sucesso!")

        print(f"Processando a imagem: {IMAGE_PATH}")
        results = model.predict(source=IMAGE_PATH, save=True, show_labels=False, conf=0.5)
        print("Processamento concluído.")

        resultado = results[0]

        # --- CORREÇÃO PRINCIPAL AQUI ---
        # Verificamos se há resultados no atributo .obb (Oriented Bounding Box)
        if resultado.obb is None or len(resultado.obb) == 0:
            print("Nenhuma partícula foi detectada na imagem.")
        else:
            print(f"\nModelo OBB detectou {len(resultado.obb)} partículas. Extraindo dados...")

            dados_particulas = []

            # Iteramos sobre os resultados de .obb
            # O formato .xywhr fornece [centro_x, centro_y, largura, altura, rotação_em_radianos]
            for box in resultado.obb:
                # Pegamos apenas a largura (w) e altura (h) da caixa
                x, y, w, h, r = box.xywhr[0].cpu().numpy()

                # Aplica a calibração para converter de pixels para milímetros
                comprimento_mm = w / PIXEL_POR_MM
                largura_mm = h / PIXEL_POR_MM

                # Calcula a razão de aspecto
                razao_aspecto = max(comprimento_mm, largura_mm) / min(comprimento_mm, largura_mm) if min(comprimento_mm,
                                                                                                         largura_mm) > 0 else 0

                dados_particulas.append({
                    'id': len(dados_particulas) + 1,
                    'comprimento': comprimento_mm,
                    'largura': largura_mm,
                    'razao_aspecto': razao_aspecto
                })

            print("\nAmostra dos dados extraídos (em mm):")
            for p in dados_particulas[:5]:  # Mostra os 5 primeiros
                print(
                    f"  ID: {p['id']}, Comprimento: {p['comprimento']:.4f}, Largura: {p['largura']:.4f}, Razão: {p['razao_aspecto']:.4f}")

            # Salva o arquivo .txt na mesma pasta da imagem de resultado
            output_dir = resultado.save_dir
            output_txt_path = os.path.join(output_dir, 'resultados_particulas.txt')

            with open(output_txt_path, 'w') as f:
                f.write("ID_Particula\tComprimento(mm)\tLargura(mm)\tRazao_Aspecto\n")
                for p in dados_particulas:
                    f.write(f"{p['id']}\t\t{p['comprimento']:.4f}\t\t{p['largura']:.4f}\t\t{p['razao_aspecto']:.4f}\n")

            print(f"\nArquivo .txt com os dados foi salvo em: '{output_txt_path}'")

        print(f"A imagem processada foi salva na pasta: '{resultado.save_dir}'")
        print("\nTeste finalizado com sucesso!")

    except Exception as e:
        import traceback

        print(f"\nOcorreu um erro durante o teste:")
        traceback.print_exc()